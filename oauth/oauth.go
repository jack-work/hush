// Package oauth lets the hush agent manage OAuth credentials on behalf of
// consuming applications: it stores the (encrypted) access+refresh token
// pair plus the metadata needed to refresh, runs a proactive refresh
// goroutine per config, and exposes lookups that never block on refresh.
//
// Tokens are persisted as age-encrypted TOML files under
// <stateDir>/oauth/<name>.toml. The token endpoint metadata is plaintext
// (URLs, client ID, scopes); only the access and refresh tokens are
// encrypted. expires_at is kept plaintext so the agent can sort startup
// state without decrypting anything.
package oauth

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"
)

// Config describes one OAuth provider's refresh endpoint.
type Config struct {
	Name         string
	AuthorizeURL string
	TokenURL     string
	RedirectURI  string
	ClientID     string
	Scopes       string
}

// Tokens are the credential values returned by an OAuth token endpoint.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // seconds; absolute expiry computed at write time
}

// Errors surfaced to clients. The agent maps these to Response.ErrorCode so
// figaro (and other callers) can branch without string matching.
var (
	ErrNotFound          = errors.New("oauth: config not registered")
	ErrRefreshPermanent  = errors.New("oauth: refresh failed permanently (re-login required)")
	ErrRefreshTransient  = errors.New("oauth: refresh failed transiently")
)

const (
	// safetyWindow is subtracted from the provider's expires_in when computing
	// the absolute expiry. Matches the figaro behavior pre-refactor.
	safetyWindow = 5 * time.Minute

	// proactiveWindow is how far before expiry the background goroutine
	// kicks off a refresh.
	proactiveWindow = 10 * time.Minute

	// minProactiveSleep keeps the background loop from spinning on
	// already-expired or near-expired tokens.
	minProactiveSleep = 1 * time.Second
)

// plaintextTokens is the cached, decrypted state for a single config.
type plaintextTokens struct {
	access    string
	refresh   string
	expiresAt time.Time
}

// configState holds the in-memory state for one OAuth config.
type configState struct {
	cfg    Config
	tokens atomic.Pointer[plaintextTokens]

	// mu serializes refresh attempts for this config and protects flight.
	mu     sync.Mutex
	flight *refreshOp

	// cancel stops the proactive refresh goroutine.
	cancel context.CancelFunc
}

// refreshOp represents an in-flight refresh attempt. Concurrent refresh
// requests coalesce by waiting on done and reading result/err.
type refreshOp struct {
	done   chan struct{}
	result string
	err    error
}

// Manager owns all OAuth state for the agent.
type Manager struct {
	stateDir   string
	identities []age.Identity
	recipient  age.Recipient
	logger     *log.Logger

	mu      sync.RWMutex
	configs map[string]*configState

	ctx    context.Context
	cancel context.CancelFunc

	// httpClient is overridable for tests.
	httpClient httpDoer
}

// NewManager builds a manager rooted at stateDir. Call Start to load
// existing configs from disk and begin proactive refresh.
func NewManager(stateDir string, identities []age.Identity, recipient age.Recipient, logger *log.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		stateDir:   stateDir,
		identities: identities,
		recipient:  recipient,
		logger:     logger,
		configs:    make(map[string]*configState),
		ctx:        ctx,
		cancel:     cancel,
		httpClient: defaultHTTPClient(),
	}
}

// Start loads any persisted configs and launches their proactive refresh
// goroutines. Safe to call when no configs exist yet (returns nil).
func (m *Manager) Start() error {
	dir := m.oauthDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := stripTOMLExt(e.Name())
		if name == "" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		cfg, tok, err := m.loadFile(path)
		if err != nil {
			m.logger.Printf("oauth: load %s: %v", e.Name(), err)
			continue
		}
		m.installState(cfg, tok)
	}
	return nil
}

// Stop cancels all proactive refresh goroutines and clears in-memory
// plaintext caches. Call from the agent's shutdown path.
func (m *Manager) Stop() {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, st := range m.configs {
		// Zeroing the plaintext is best-effort; Go strings are immutable.
		st.tokens.Store(nil)
	}
}

// Register creates or replaces the config and tokens for name. The new
// tokens are persisted and become immediately visible to readers. The
// previous proactive refresh goroutine (if any) is cancelled and a fresh
// one is started.
func (m *Manager) Register(cfg Config, tok Tokens) error {
	if cfg.Name == "" {
		return errors.New("oauth: config name is required")
	}
	if cfg.TokenURL == "" {
		return errors.New("oauth: token_url is required")
	}
	if cfg.ClientID == "" {
		return errors.New("oauth: client_id is required")
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		return errors.New("oauth: access and refresh tokens are both required")
	}

	expiresAt := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-safetyWindow)

	if err := m.saveFile(cfg, plaintextTokens{
		access:    tok.AccessToken,
		refresh:   tok.RefreshToken,
		expiresAt: expiresAt,
	}); err != nil {
		return err
	}

	m.installState(cfg, plaintextTokens{
		access:    tok.AccessToken,
		refresh:   tok.RefreshToken,
		expiresAt: expiresAt,
	})
	return nil
}

// Get returns the cached access token for name. Never blocks on refresh;
// returns whatever is currently in the cache (which may be clock-expired —
// callers detect that via 401 from the provider and call Refresh).
func (m *Manager) Get(name string) (string, error) {
	st := m.lookup(name)
	if st == nil {
		return "", ErrNotFound
	}
	p := st.tokens.Load()
	if p == nil {
		return "", ErrNotFound
	}
	return p.access, nil
}

// Refresh forces a refresh for name, coalescing with any in-flight refresh
// for the same config. Returns the new access token.
func (m *Manager) Refresh(name string) (string, error) {
	st := m.lookup(name)
	if st == nil {
		return "", ErrNotFound
	}
	return m.doRefresh(st)
}

// Delete removes the on-disk state and stops the proactive goroutine.
func (m *Manager) Delete(name string) error {
	m.mu.Lock()
	st, ok := m.configs[name]
	if ok {
		delete(m.configs, name)
	}
	m.mu.Unlock()

	if st != nil && st.cancel != nil {
		st.cancel()
	}

	path := m.filePath(name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// List returns the names of all currently registered OAuth configs.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.configs))
	for n := range m.configs {
		names = append(names, n)
	}
	return names
}

// installState atomically replaces (or creates) the in-memory state for
// cfg.Name, cancels any old proactive goroutine, and starts a fresh one.
func (m *Manager) installState(cfg Config, tok plaintextTokens) {
	m.mu.Lock()
	old, exists := m.configs[cfg.Name]
	if exists && old.cancel != nil {
		old.cancel()
	}

	ctx, cancel := context.WithCancel(m.ctx)
	st := &configState{cfg: cfg, cancel: cancel}
	st.tokens.Store(&tok)
	m.configs[cfg.Name] = st
	m.mu.Unlock()

	go m.proactiveLoop(ctx, st)
}

func (m *Manager) lookup(name string) *configState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configs[name]
}

// proactiveLoop refreshes a token shortly before it expires. Backs off on
// transient failures; exits permanently on hard failures.
func (m *Manager) proactiveLoop(ctx context.Context, st *configState) {
	backoff := time.Second
	for {
		p := st.tokens.Load()
		if p == nil {
			return
		}
		wait := time.Until(p.expiresAt.Add(-proactiveWindow))
		if wait < minProactiveSleep {
			wait = minProactiveSleep
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		_, err := m.doRefresh(st)
		if err == nil {
			backoff = time.Second
			continue
		}
		if errors.Is(err, ErrRefreshPermanent) {
			m.logger.Printf("oauth: %s refresh failed permanently, proactive loop stopping", st.cfg.Name)
			return
		}
		m.logger.Printf("oauth: %s transient refresh failure, retrying in %s: %v", st.cfg.Name, backoff, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Minute {
			backoff *= 4
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
		}
	}
}
