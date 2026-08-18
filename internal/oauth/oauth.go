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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"
)

// Config describes one credential: where to mint an access token, and by
// which grant.
type Config struct {
	Name         string
	AuthorizeURL string
	TokenURL     string
	RedirectURI  string
	ClientID     string
	Scopes       string

	// Grant selects the minting strategy (see grant.go). Empty means
	// refresh_token, so every file written by an older hush loads and
	// behaves exactly as it did.
	Grant string
}

// Tokens are the credential values a grant returns.
type Tokens struct {
	AccessToken string
	// RefreshToken is the DURABLE secret: a rotating refresh token under
	// the refresh_token grant, a stable one (a GitHub access token) under
	// an exchange. Either way it is what the next mint is made from.
	RefreshToken string
	ExpiresIn    int // seconds; absolute expiry computed at write time

	// Metadata carries non-secret facts that arrived WITH the token and
	// are useless without it: Copilot's exchange answers with the API host
	// to spend the session token at. Readers get it from Get.
	Metadata map[string]string
}

// Errors surfaced to clients. The agent maps these to Response.ErrorCode so
// figaro (and other callers) can branch without string matching.
var (
	ErrNotFound         = errors.New("oauth: config not registered")
	ErrRefreshPermanent = errors.New("oauth: refresh failed permanently (re-login required)")
	ErrRefreshTransient = errors.New("oauth: refresh failed transiently")
)

const (
	// refreshFraction is how much of a token's lifetime elapses before the
	// proactive loop renews it. Everything here is *relative to the actual
	// lifetime* the provider handed us, which is the whole point: a fixed
	// window (the old proactiveWindow = 10m) is catastrophic against a
	// provider that issues short tokens. Authelia's default access token
	// lives 10 minutes, so "refresh 10 minutes before expiry" meant "refresh
	// immediately, forever" — one rotation per second, ~2000 per hour per
	// client, until some crash lost a write and the chain snapped.
	refreshFraction = 0.7

	// minRefreshInterval is the floor on the proactive loop's sleep. It is a
	// guard rail against exactly the runaway above: no arithmetic mistake,
	// clock jump, or provider returning expires_in=0 can cost more than one
	// refresh per minute.
	minRefreshInterval = 1 * time.Minute

	// maxRefreshInterval caps the sleep so a very long-lived token still gets
	// exercised occasionally — a refresh that has silently started failing is
	// better discovered while the current token is valid.
	maxRefreshInterval = 6 * time.Hour

	// defaultLifetime is assumed when the provider omits expires_in.
	defaultLifetime = 1 * time.Hour
)

// plaintextTokens is the cached, decrypted state for a single config.
type plaintextTokens struct {
	access  string
	refresh string

	// metadata is non-secret and travels with the access token: it is
	// re-minted with it, so it can never describe a token that is gone.
	metadata map[string]string

	// prevRefresh is the refresh token this one replaced. Providers that
	// rotate on every refresh (Authelia) leave no way to recover if the new
	// token is lost between the HTTP response and the disk write, so we keep
	// the immediate predecessor as a one-step fallback.
	prevRefresh string

	issuedAt  time.Time
	expiresAt time.Time
}

// newTokenState builds the cached state for a freshly minted token pair.
// The single place where lifetime arithmetic happens.
func newTokenState(tok Tokens, prevRefresh string, now time.Time) plaintextTokens {
	lifetime := time.Duration(tok.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = defaultLifetime
	}
	return plaintextTokens{
		access:      tok.AccessToken,
		refresh:     tok.RefreshToken,
		metadata:    tok.Metadata,
		prevRefresh: prevRefresh,
		issuedAt:    now,
		expiresAt:   now.Add(lifetime),
	}
}

// refreshAt reports when the proactive loop should renew this token:
// refreshFraction of the way through its lifetime. Tokens loaded from a
// file written by an older hush have no issued_at, so their remaining
// lifetime stands in for the whole.
func (p plaintextTokens) refreshAt(now time.Time) time.Time {
	start, lifetime := p.issuedAt, p.expiresAt.Sub(p.issuedAt)
	if start.IsZero() || lifetime <= 0 {
		start, lifetime = now, p.expiresAt.Sub(now)
	}
	if lifetime <= 0 {
		return now
	}
	return start.Add(time.Duration(float64(lifetime) * refreshFraction))
}

// proactiveWait is how long the background loop sleeps before renewing p,
// clamped to [minRefreshInterval, maxRefreshInterval].
func proactiveWait(p plaintextTokens, now time.Time) time.Duration {
	wait := p.refreshAt(now).Sub(now)
	if wait < minRefreshInterval {
		return minRefreshInterval
	}
	if wait > maxRefreshInterval {
		return maxRefreshInterval
	}
	return wait
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
	g, err := grantFor(cfg)
	if err != nil {
		return err
	}
	if err := g.Validate(cfg, tok); err != nil {
		return err
	}

	// An exchange registers with only the durable secret. Mint the first
	// access token here rather than leaving readers to discover on their
	// first call whether the credential was ever any good.
	if tok.AccessToken == "" && g.MintsOnRegister() {
		minted, err := g.Mint(m.ctx, m.httpClient, cfg, tok.RefreshToken)
		if err != nil {
			return fmt.Errorf("oauth: %s: first mint failed: %w", cfg.Name, err)
		}
		tok = minted
	}

	state := newTokenState(tok, "", time.Now())

	if err := m.saveFile(cfg, state); err != nil {
		return err
	}

	m.installState(cfg, state)
	return nil
}

// Get returns the cached access token for name. Never blocks on refresh;
// returns whatever is currently in the cache (which may be clock-expired —
// callers detect that via 401 from the provider and call Refresh).
func (m *Manager) Get(name string) (string, error) {
	tok, _, err := m.GetFull(name)
	return tok, err
}

// GetFull returns the cached access token and the metadata minted with it.
// Same non-blocking contract as Get.
func (m *Manager) GetFull(name string) (string, map[string]string, error) {
	st := m.lookup(name)
	if st == nil {
		return "", nil, ErrNotFound
	}
	p := st.tokens.Load()
	if p == nil {
		return "", nil, ErrNotFound
	}
	return p.access, cloneMeta(p.metadata), nil
}

// RefreshFull forces a mint and returns the new token with its metadata.
func (m *Manager) RefreshFull(name string) (string, map[string]string, error) {
	tok, err := m.Refresh(name)
	if err != nil {
		return "", nil, err
	}
	st := m.lookup(name)
	if st == nil {
		return tok, nil, nil
	}
	p := st.tokens.Load()
	if p == nil {
		return tok, nil, nil
	}
	return tok, cloneMeta(p.metadata), nil
}

func cloneMeta(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
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

// proactiveLoop refreshes a token partway through its lifetime. Backs off on
// transient failures; exits permanently on hard failures.
func (m *Manager) proactiveLoop(ctx context.Context, st *configState) {
	backoff := time.Second
	for {
		p := st.tokens.Load()
		if p == nil {
			return
		}
		wait := proactiveWait(*p, time.Now())

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
