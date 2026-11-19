//go:build linux

package credserve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"time"
)

// SystemdFDName is the socket-activation name of the LoadCredential socket. No
// principal may take it, so the descriptor is never mistaken for one.
const SystemdFDName = "loadcredential"

// Systemd is the LoadCredential socket: a unit that says
// LoadCredential=<id>:<socket> receives the raw token of the instance its
// grant names, or nothing at all.
type Systemd struct {
	Socket string `toml:"socket"`
	// ManagerUID is the only peer uid served: systemd's own (0). A process
	// can bind any abstract address it likes, so the unit name in the address
	// is believed only from this uid.
	ManagerUID uint32 `toml:"manager_uid"`
	// Units maps a unit name to its grants: credential id -> instance.
	Units map[string]map[string]string `toml:"units"`
}

var (
	unitNameRE     = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+\.(service|socket|mount|timer|path|swap|target|scope|slice)$`)
	credentialIDRE = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,255}$`)
)

func (sd *Systemd) validate(instances map[string]Instance) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("cred config: systemd: "+format, a...)
	}
	if !strings.HasPrefix(sd.Socket, "/") {
		return fail("socket %q is not an absolute path", sd.Socket)
	}
	if len(sd.Units) == 0 {
		return fail("units is required")
	}
	for unit, grants := range sd.Units {
		if !unitNameRE.MatchString(unit) {
			return fail("unit %q is not a unit name", unit)
		}
		if len(grants) == 0 {
			return fail("unit %s grants nothing", unit)
		}
		for id, inst := range grants {
			if !credentialIDRE.MatchString(id) || id == "." || id == ".." {
				return fail("unit %s: credential id %q is not a credential name", unit, id)
			}
			if _, ok := instances[inst]; !ok {
				return fail("unit %s: credential %s: %q is not an instance", unit, id, inst)
			}
		}
	}
	return nil
}

// parseSystemdPeer reads the address systemd binds before it connects for
// LoadCredential=: abstract "\0<random>/unit/<unit>/<id>", which Go shows with
// a leading '@'. Anything else is not systemd.
func parseSystemdPeer(addr net.Addr) (unit, id string, ok bool) {
	ua, isUnix := addr.(*net.UnixAddr)
	if !isUnix || !strings.HasPrefix(ua.Name, "@") {
		return "", "", false
	}
	parts := strings.Split(ua.Name[1:], "/")
	if len(parts) != 4 || parts[1] != "unit" || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

// systemdTimeout bounds one LoadCredential connection, an exec instance's
// command included (its own timeout defaults to 30 s).
const systemdTimeout = 2 * time.Minute

// ServeSystemd answers systemd's LoadCredential connections on ln until ctx
// ends. It writes the raw token and closes, or closes having written nothing:
// systemd then starts the unit with an EMPTY credential, so a consumer must
// treat an empty file as a failure.
func (s *Server) ServeSystemd(ctx context.Context, ln net.Listener) error {
	if s.cfg.Systemd == nil {
		return errors.New("systemd socket: no [systemd] in the config")
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.connections.Add(1)
		go func() {
			defer s.connections.Done()
			s.answerSystemd(c)
		}()
	}
}

func (s *Server) answerSystemd(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(systemdTimeout))
	sd := s.cfg.Systemd
	uid, err := peerUID(c)
	if err != nil {
		s.logger.Printf("systemd: REFUSED a peer without credentials")
		return
	}
	unit, id, ok := parseSystemdPeer(c.RemoteAddr())
	if uid != sd.ManagerUID {
		s.logger.Printf("systemd: REFUSED uid %d (only the system manager, uid %d)", uid, sd.ManagerUID)
		return
	}
	if !ok {
		s.logger.Printf("systemd: REFUSED a peer whose address is not systemd's /unit/<unit>/<id>")
		return
	}
	name := sd.Units[unit][id]
	if name == "" {
		s.logger.Printf("systemd: REFUSED %s credential %q: no grant", unit, id)
		return
	}
	token, status := s.rawToken(name)
	if s.cfg.Instances[name].Audit {
		s.logger.Printf("cred: audit %s principal=systemd:%s uid=%d -> %d", name, unit, uid, status)
	}
	if token == "" {
		s.logger.Printf("systemd: REFUSED %s to %s as %q: credential unavailable (%d)", name, unit, id, status)
		return
	}
	if _, err := c.Write([]byte(token)); err != nil {
		s.logger.Printf("systemd: %s to %s as %q: write failed", name, unit, id)
		return
	}
	s.logger.Printf("systemd: delivered %s to %s as %q", name, unit, id)
}

// rawToken runs the same answer GET /cred/<name> gives (refresh, pacing,
// stale pins and all) and returns its token, or "" with the status it failed on.
func (s *Server) rawToken(name string) (string, int) {
	rec := httptest.NewRecorder()
	s.answer(rec, name)
	if rec.Code != http.StatusOK {
		return "", rec.Code
	}
	var doc struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || doc.Token == "" {
		return "", http.StatusBadGateway
	}
	return doc.Token, http.StatusOK
}
