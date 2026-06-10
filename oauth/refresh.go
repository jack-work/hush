package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

	tok, err := m.refreshHTTP(st)
	if err == nil {
		expiresAt := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-safetyWindow)
		newTok := plaintextTokens{
			access:    tok.AccessToken,
			refresh:   tok.RefreshToken,
			expiresAt: expiresAt,
		}
		// Persist first; only update memory if the write succeeded so a
		// crash mid-refresh can't lose the new refresh token.
		if perr := m.saveFile(st.cfg, newTok); perr != nil {
			err = fmt.Errorf("oauth: persist refreshed tokens: %w", perr)
		} else {
			st.tokens.Store(&newTok)
		}
	} else if errors.Is(err, ErrRefreshPermanent) {
		// A permanent rejection usually means our refresh token was
		// rotated away by another process whose success is already on
		// disk. Adopt the newer disk state instead of failing.
		if disk, ok := m.newerOnDisk(st); ok {
			m.logger.Printf("oauth: %s refresh rejected; adopting newer tokens from disk (rotated by another process)", st.cfg.Name)
			st.tokens.Store(&disk)
			tok = Tokens{AccessToken: disk.access}
			err = nil
		}
	}

	var resultTok string
	if err == nil {
		resultTok = tok.AccessToken
	}

	st.mu.Lock()
	op.result = resultTok
	op.err = err
	close(op.done)
	st.flight = nil
	st.mu.Unlock()

	return resultTok, err
}

// refreshHTTP makes the token-endpoint POST.
func (m *Manager) refreshHTTP(st *configState) (Tokens, error) {
	p := st.tokens.Load()
	if p == nil {
		return Tokens{}, ErrNotFound
	}

	bodyBytes, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     st.cfg.ClientID,
		"refresh_token": p.refresh,
	})

	req, err := http.NewRequestWithContext(m.ctx, "POST", st.cfg.TokenURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: build request: %v", ErrRefreshTransient, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: %v", ErrRefreshTransient, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 500 {
		return Tokens{}, fmt.Errorf("%w: token endpoint %d: %s", ErrRefreshTransient, resp.StatusCode, string(body))
	}
	if resp.StatusCode != 200 {
		// 4xx — refresh token rejected. Caller needs to re-login.
		return Tokens{}, fmt.Errorf("%w: token endpoint %d: %s", ErrRefreshPermanent, resp.StatusCode, string(body))
	}

	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Tokens{}, fmt.Errorf("%w: parse token response: %v", ErrRefreshTransient, err)
	}
	if parsed.AccessToken == "" {
		return Tokens{}, fmt.Errorf("%w: token endpoint returned empty access_token", ErrRefreshPermanent)
	}
	// Some providers omit refresh_token on refresh (no rotation). Keep the old one.
	if parsed.RefreshToken == "" {
		parsed.RefreshToken = p.refresh
	}
	return Tokens{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresIn:    parsed.ExpiresIn,
	}, nil
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
