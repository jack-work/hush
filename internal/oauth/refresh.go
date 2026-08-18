package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// httpDoer lets tests inject a fake transport.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// doRefresh performs (or joins) a refresh for one config and atomically
// updates the in-memory and on-disk state. Concurrent refresh requests for
// the same config coalesce into a single HTTP call.
func (m *Manager) doRefresh(st *configState) (string, error) {
	st.mu.Lock()
	if st.flight != nil {
		existing := st.flight
		st.mu.Unlock()
		<-existing.done
		return existing.result, existing.err
	}
	op := &refreshOp{done: make(chan struct{})}
	st.flight = op
	st.mu.Unlock()

	cur := st.tokens.Load()
	tok, err := m.mint(st, currentRefresh(cur))
	if errors.Is(err, ErrRefreshPermanent) {
		// A permanent rejection usually means our refresh token was
		// rotated away by another process whose success is already on
		// disk. Adopt the newer disk state instead of failing.
		if disk, ok := m.newerOnDisk(st); ok {
			m.logger.Printf("oauth: %s refresh rejected; adopting newer tokens from disk (rotated by another process)", st.cfg.Name)
			st.tokens.Store(&disk)
			m.finish(op, st, disk.access, nil)
			return disk.access, nil
		}
		// Otherwise our token may be one rotation ahead of what the
		// provider knows: a response we received but never persisted.
		// The predecessor is the only other candidate — try it once.
		if prev := previousRefresh(cur); prev != "" {
			m.logger.Printf("oauth: %s refresh rejected; retrying with the previous refresh token", st.cfg.Name)
			if prevTok, prevErr := m.mint(st, prev); prevErr == nil {
				tok, err = prevTok, nil
			}
		}
	}

	if err == nil {
		newTok := newTokenState(tok, currentRefresh(cur), time.Now())
		// Persist first; only update memory if the write succeeded so a
		// crash mid-refresh can't lose the new refresh token.
		if perr := m.saveFile(st.cfg, newTok); perr != nil {
			err = fmt.Errorf("oauth: persist refreshed tokens: %w", perr)
		} else {
			st.tokens.Store(&newTok)
		}
	}

	var resultTok string
	if err == nil {
		resultTok = tok.AccessToken
	}
	m.finish(op, st, resultTok, err)
	return resultTok, err
}

// finish publishes the outcome to any callers coalesced onto op and clears
// the in-flight slot.
func (m *Manager) finish(op *refreshOp, st *configState, result string, err error) {
	st.mu.Lock()
	op.result = result
	op.err = err
	close(op.done)
	st.flight = nil
	st.mu.Unlock()
}

// mint asks the config's grant for a fresh access token. The manager knows
// nothing about wire formats; this is the only door to one.
func (m *Manager) mint(st *configState, durable string) (Tokens, error) {
	g, err := grantFor(st.cfg)
	if err != nil {
		return Tokens{}, err
	}
	return g.Mint(m.ctx, m.httpClient, st.cfg, durable)
}

// currentRefresh and previousRefresh read a possibly-nil cached state.
func currentRefresh(p *plaintextTokens) string {
	if p == nil {
		return ""
	}
	return p.refresh
}

func previousRefresh(p *plaintextTokens) string {
	if p == nil {
		return ""
	}
	return p.prevRefresh
}

// newerOnDisk loads the persisted tokens for st and reports whether they
// differ from the in-memory ones. A difference means another process
// refreshed successfully after we loaded ours, so its rotated tokens
// supersede our rejected ones.
func (m *Manager) newerOnDisk(st *configState) (plaintextTokens, bool) {
	_, tok, err := m.loadFile(m.filePath(st.cfg.Name))
	if err != nil {
		return plaintextTokens{}, false
	}
	cur := st.tokens.Load()
	if cur != nil && tok.access == cur.access && tok.refresh == cur.refresh {
		return plaintextTokens{}, false
	}
	return tok, true
}
