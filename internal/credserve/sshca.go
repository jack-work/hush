//go:build linux

package credserve

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"

	"github.com/jack-work/hush/internal/secrets"
)

// KindSSHCA is an SSH host certificate authority whose private keys never
// leave this process in the clear: the state file holds them age-encrypted
// to the config's recipient. It keeps two keys, current (signs) and next
// (published early, so nodes trust it before it ever signs). Routes, on the
// owner socket and on any principal socket granted the instance:
//
//	GET  /ssh-ca/<name>/pub        {"current": "<pub>", "next": "<pub>"}
//	POST /ssh-ca/<name>/sign-host  {"node": "<n>", "public_key": "<pub>"} -> {"certificate": "<cert>"}
//	POST /ssh-ca/<name>/rotate     next becomes current, a new next is minted;
//	                               with no state yet, mints both (init)
//
// rotate needs a live consent grant for "ssh-ca-rotate:<name>" to the
// calling principal (or "owner") in grants_file: the row band-grants writes
// when the Boss approves on /grants/ with his passkey. Nothing rotates
// without it. A host cert names the node only (principal = node name): every
// fleet node is reached as 127.0.0.1:<port>, so an address principal would
// make one node's cert valid for every node.
const KindSSHCA = "ssh-ca"

const (
	sshCADefaultValidity = 35 * 24 * time.Hour
	sshCAMaxValidity     = 90 * 24 * time.Hour
	sshCADefaultGrants   = "/var/lib/band-grants/grants.json"
	sshCABackdate        = 5 * time.Minute
)

var sshNodeRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func (in Instance) validateSSHCA(name string) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("cred config: instance %s: "+format, append([]any{name}, a...)...)
	}
	if in.AuthorizeURL != "" || in.TokenURL != "" || in.RedirectURI != "" || in.ClientID != "" || in.Scopes != "" ||
		in.DeviceURL != "" || in.GitHubTokenURL != "" || len(in.Command) > 0 || in.Timeout != "" {
		return fail("kind %q takes validity and grants_file only", KindSSHCA)
	}
	if _, err := in.sshCAValidity(); err != nil {
		return fail("%v", err)
	}
	if in.GrantsFile != "" && !strings.HasPrefix(in.GrantsFile, "/") {
		return fail("grants_file %q is not an absolute path", in.GrantsFile)
	}
	return nil
}

func (in Instance) sshCAValidity() (time.Duration, error) {
	if in.Validity == "" {
		return sshCADefaultValidity, nil
	}
	d, err := time.ParseDuration(in.Validity)
	if err != nil {
		return 0, fmt.Errorf("validity: %w", err)
	}
	if d < time.Hour || d > sshCAMaxValidity {
		return 0, fmt.Errorf("validity %s is outside 1h..%s", d, sshCAMaxValidity)
	}
	return d, nil
}

func (in Instance) sshCAGrantsFile() string {
	if in.GrantsFile == "" {
		return sshCADefaultGrants
	}
	return in.GrantsFile
}

// SetSSHCA gives the server what the ssh-ca routes need: the state
// directory (the one LockState holds) and the age identities that open it.
func (s *Server) SetSSHCA(stateDir string, ids []age.Identity) {
	s.sshCADir = filepath.Join(stateDir, "ssh-ca")
	s.sshCAIDs = ids
}

type sshCAState struct {
	Current    string `toml:"current"`
	CurrentPub string `toml:"current_pub"`
	Next       string `toml:"next"`
	NextPub    string `toml:"next_pub"`
	Rotated    string `toml:"rotated"`
}

func (s *Server) sshCAPath(name string) string { return filepath.Join(s.sshCADir, name+".toml") }

func (s *Server) loadSSHCA(name string) (*sshCAState, error) {
	raw, err := os.ReadFile(s.sshCAPath(name))
	if err != nil {
		return nil, err
	}
	var st sshCAState
	if _, err := toml.Decode(string(raw), &st); err != nil {
		return nil, fmt.Errorf("ssh-ca %s state: %w", name, err)
	}
	if st.Current == "" || st.Next == "" || st.CurrentPub == "" || st.NextPub == "" {
		return nil, fmt.Errorf("ssh-ca %s state is incomplete", name)
	}
	return &st, nil
}

func (s *Server) saveSSHCA(name string, st *sshCAState) error {
	if err := os.MkdirAll(s.sshCADir, 0o700); err != nil {
		return err
	}
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(st); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.sshCADir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.WriteString(tmp, b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.sshCAPath(name))
}

// mintSSHCAKey makes a fresh ed25519 CA key and returns it sealed to the
// recipient plus its public line. The private key exists only in memory.
func mintSSHCAKey(recipient age.Recipient, comment string) (sealed, pub string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", "", err
	}
	sealed, err = secrets.EncryptValue(string(pem.EncodeToMemory(block)), recipient)
	if err != nil {
		return "", "", err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", err
	}
	return sealed, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " " + comment, nil
}

func (s *Server) sshCASigner(st *sshCAState) (ssh.Signer, error) {
	pemText, err := secrets.DecryptValue(st.Current, s.sshCAIDs)
	if err != nil {
		return nil, fmt.Errorf("open current CA key: %w", err)
	}
	return ssh.ParsePrivateKey([]byte(pemText))
}

// sshCARoute answers /ssh-ca/<name>/<op>; granted says whether the caller
// may use instance <name> at all (the owner socket may; a principal socket
// only for its credentials). who names the caller for the grant check and
// the audit line.
func (s *Server) sshCARoute(w http.ResponseWriter, r *http.Request, who string, granted func(string) bool) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, "/ssh-ca/")
	if !ok {
		return false
	}
	name, op, _ := strings.Cut(rest, "/")
	in, exists := s.cfg.Instances[name]
	if !granted(name) {
		s.logger.Printf("ssh-ca: REFUSED %s %s for %s: not granted", op, name, who)
		writeError(w, http.StatusForbidden, "not_granted", fmt.Sprintf("credential %q is not granted to %s", name, who))
		return true
	}
	if !exists || in.Kind != KindSSHCA {
		writeError(w, http.StatusNotFound, "unknown_credential", "no such ssh-ca instance")
		return true
	}
	if s.sshCADir == "" {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "ssh-ca state is not configured")
		return true
	}
	s.sshCAMu.Lock()
	defer s.sshCAMu.Unlock()
	switch {
	case op == "pub" && r.Method == http.MethodGet:
		st, err := s.loadSSHCA(name)
		if err != nil {
			s.writeSSHCAMissing(w, name, err)
			return true
		}
		writeJSON(w, map[string]string{"current": st.CurrentPub, "next": st.NextPub})
	case op == "sign-host" && r.Method == http.MethodPost:
		s.sshCASign(w, r, name, in, who)
	case op == "rotate" && r.Method == http.MethodPost:
		s.sshCARotate(w, name, in, who)
	default:
		writeError(w, http.StatusNotFound, "not_found", "GET /ssh-ca/<name>/pub, POST /ssh-ca/<name>/sign-host or /rotate")
	}
	return true
}

func (s *Server) writeSSHCAMissing(w http.ResponseWriter, name string, err error) {
	if errors.Is(err, fs.ErrNotExist) {
		writeError(w, http.StatusConflict, "no_ca", fmt.Sprintf("ssh-ca %s has no keys yet: rotate (with the Boss's grant) mints them", name))
		return
	}
	s.logger.Printf("ssh-ca: %s: %v", name, err)
	writeError(w, http.StatusInternalServerError, "state_error", "ssh-ca state unreadable")
}

func (s *Server) sshCASign(w http.ResponseWriter, r *http.Request, name string, in Instance, who string) {
	var req struct {
		Node      string `json:"node"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be JSON {node, public_key}")
		return
	}
	if !sshNodeRE.MatchString(req.Node) {
		writeError(w, http.StatusBadRequest, "bad_node", fmt.Sprintf("node must match %s", sshNodeRE))
		return
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_key", "public_key is not an OpenSSH public key line")
		return
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		writeError(w, http.StatusBadRequest, "bad_key", "public_key is a certificate, not a host key")
		return
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		writeError(w, http.StatusBadRequest, "bad_key", "host keys must be ed25519")
		return
	}
	st, err := s.loadSSHCA(name)
	if err != nil {
		s.writeSSHCAMissing(w, name, err)
		return
	}
	signer, err := s.sshCASigner(st)
	if err != nil {
		s.logger.Printf("ssh-ca: %s: %v", name, err)
		writeError(w, http.StatusInternalServerError, "state_error", "cannot open the CA key")
		return
	}
	validity, _ := in.sshCAValidity()
	now := s.Now()
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		writeError(w, http.StatusInternalServerError, "rand", "no randomness")
		return
	}
	cert := &ssh.Certificate{
		Key:             key,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.HostCert,
		KeyId:           fmt.Sprintf("host:%s:%s", req.Node, now.UTC().Format("20060102T150405Z")),
		ValidPrincipals: []string{req.Node},
		ValidAfter:      uint64(now.Add(-sshCABackdate).Unix()),
		ValidBefore:     uint64(now.Add(validity).Unix()),
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		s.logger.Printf("ssh-ca: %s: sign: %v", name, err)
		writeError(w, http.StatusInternalServerError, "sign_failed", "signing failed")
		return
	}
	s.logger.Printf("ssh-ca: audit sign-host %s node=%s fp=%s serial=%d until=%s by %s", name, req.Node,
		ssh.FingerprintSHA256(key), cert.Serial, time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC3339), who)
	writeJSON(w, map[string]string{"certificate": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))})
}

func (s *Server) sshCARotate(w http.ResponseWriter, name string, in Instance, who string) {
	cred := "ssh-ca-rotate:" + name
	if !liveConsentGrant(in.sshCAGrantsFile(), who, cred, s.Now()) {
		s.logger.Printf("ssh-ca: REFUSED rotate %s by %s: no live consent grant %q", name, who, cred)
		writeError(w, http.StatusForbidden, "no_grant", fmt.Sprintf("rotate needs a live consent grant %q for %s (approve on /grants/)", cred, who))
		return
	}
	stamp := s.Now().UTC().Format("20060102")
	st, err := s.loadSSHCA(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		cur, curPub, err1 := mintSSHCAKey(s.cfg.RecipientKey(), "hush-ssh-ca:"+name+":"+stamp+"a")
		nxt, nxtPub, err2 := mintSSHCAKey(s.cfg.RecipientKey(), "hush-ssh-ca:"+name+":"+stamp+"b")
		if err := errors.Join(err1, err2); err != nil {
			writeError(w, http.StatusInternalServerError, "mint_failed", "minting failed")
			return
		}
		st = &sshCAState{Current: cur, CurrentPub: curPub, Next: nxt, NextPub: nxtPub}
	case err != nil:
		s.writeSSHCAMissing(w, name, err)
		return
	default:
		nxt, nxtPub, err := mintSSHCAKey(s.cfg.RecipientKey(), "hush-ssh-ca:"+name+":"+stamp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "mint_failed", "minting failed")
			return
		}
		st.Current, st.CurrentPub, st.Next, st.NextPub = st.Next, st.NextPub, nxt, nxtPub
	}
	st.Rotated = s.Now().UTC().Format(time.RFC3339)
	if err := s.saveSSHCA(name, st); err != nil {
		s.logger.Printf("ssh-ca: %s: save: %v", name, err)
		writeError(w, http.StatusInternalServerError, "state_error", "cannot write the ssh-ca state")
		return
	}
	s.logger.Printf("ssh-ca: audit rotate %s by %s: current=%s next=%s", name, who, keyFP(st.CurrentPub), keyFP(st.NextPub))
	writeJSON(w, map[string]string{"current": st.CurrentPub, "next": st.NextPub})
}

func keyFP(line string) string {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "?"
	}
	return ssh.FingerprintSHA256(k)
}

// liveConsentGrant reports whether grants (band-grants' grants.json: one
// writer, atomic rename) holds a row for principal -> credential whose
// expires_at is in the future. Expiry is checked here, at use, so a grant
// dies on time even if band-grants' sweeper is down; a missing or unreadable
// file grants nothing.
func liveConsentGrant(path, principal, credential string, now time.Time) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc struct {
		Grants []struct {
			Principal  string  `json:"principal"`
			Credential string  `json:"credential"`
			ExpiresAt  float64 `json:"expires_at"`
		} `json:"grants"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	t := float64(now.UnixNano()) / 1e9
	for _, g := range doc.Grants {
		if g.Principal == principal && g.Credential == credential && g.ExpiresAt > t {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
