package credserve

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ConsentGrant is one row of the consent grants file: a principal may take one
// credential until ExpiresAt (unix seconds). The file belongs to its writer
// (one writer, atomic rename); hush only reads it.
type ConsentGrant struct {
	ID         string  `json:"id"`
	Principal  string  `json:"principal"`
	Credential string  `json:"credential"`
	ExpiresAt  float64 `json:"expires_at"`
	ApprovedBy string  `json:"approved_by"`
}

// maxConsentFile bounds one read of the grants file.
const maxConsentFile = 4 << 20

// readConsentGrants reads the grants file now. Any failure grants nothing.
func readConsentGrants(path string) ([]ConsentGrant, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConsentFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConsentFile {
		return nil, fmt.Errorf("larger than %d bytes", maxConsentFile)
	}
	var doc struct {
		Grants []ConsentGrant `json:"grants"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Grants, nil
}

// liveConsent returns the LIVE grant for principal -> credential in the file at
// path, read at this use. Expiry is checked here, so a grant dies at its
// expires_at even if the writer's sweeper is down.
func liveConsent(path, principal, credential string, now time.Time) (ConsentGrant, bool, error) {
	grants, err := readConsentGrants(path)
	if err != nil {
		return ConsentGrant{}, false, err
	}
	t := float64(now.UnixNano()) / 1e9
	for _, g := range grants {
		if g.Principal == principal && g.Credential == credential && g.ExpiresAt > t {
			return g, true, nil
		}
	}
	return ConsentGrant{}, false, nil
}

// errNotGranted is what authorizeCred answers for a credential the principal
// may not take, by config or by a live consent grant.
var errNotGranted = errors.New("not granted")

// authorizeCred is the ONE grant check for every route that hands a principal a
// credential: a static grant from the config, else a live consent grant from
// the consent grants file. A nil grant with a nil error is a static grant.
func (s *Server) authorizeCred(p PrincipalAuth, credential string) (*ConsentGrant, error) {
	if p.Credentials[credential] {
		return nil, nil
	}
	if s.cfg.ConsentGrants == "" {
		return nil, errNotGranted
	}
	g, ok, err := liveConsent(s.cfg.ConsentGrants, p.Name, credential, s.Now())
	if err != nil {
		s.logger.Printf("cred: consent grants unreadable (%v): granting nothing", err)
		return nil, errNotGranted
	}
	if !ok {
		return nil, errNotGranted
	}
	return &g, nil
}
