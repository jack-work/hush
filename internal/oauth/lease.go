package oauth

import (
	"net/http"
	"time"
)

type Lease struct {
	Config       Config
	AccessToken  string
	AccountID    string
	ExpiresAt    time.Time
	RefreshAt    time.Time
	SignInNeeded bool
}

func (m *Manager) Lease(name string) (Lease, error) {
	if err := m.begin(); err != nil {
		return Lease{}, err
	}
	defer m.work.Done()
	st := m.lookup(name)
	if st == nil {
		return Lease{}, ErrNotFound
	}
	p := st.tokens.Load()
	if p == nil {
		return Lease{}, ErrNotFound
	}
	return Lease{
		Config:       st.cfg,
		AccessToken:  p.access,
		AccountID:    p.metadata["account_id"],
		ExpiresAt:    p.expiresAt,
		RefreshAt:    p.refreshAt(m.now()),
		SignInNeeded: p.relogin != "",
	}, nil
}

func (m *Manager) Adopt(name string) error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.work.Done()
	cfg, tok, _, err := m.loadFile(m.filePath(name))
	if err != nil {
		return err
	}
	m.installState(cfg, tok)
	return nil
}

func (m *Manager) SetHTTPClient(c *http.Client) error {
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()
	if m.stopping {
		return ErrStopped
	}
	m.httpClient = c
	return nil
}
