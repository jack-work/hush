package oauth

import (
	"context"
	"errors"
	"net/url"
)

var ErrOperationBusy = errors.New("oauth: credential operation busy")

func (m *Manager) BeginLogin(name string) error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.work.Done()
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	if m.logins[name] {
		return ErrOperationBusy
	}
	if st := m.lookup(name); st != nil {
		st.mu.Lock()
		busy := st.flight != nil
		st.mu.Unlock()
		if busy {
			return ErrOperationBusy
		}
	}
	if m.logins == nil {
		m.logins = map[string]bool{}
	}
	m.logins[name] = true
	return nil
}

func (m *Manager) CancelLogin(name string) {
	m.loginMu.Lock()
	delete(m.logins, name)
	m.loginMu.Unlock()
}

func (m *Manager) CompleteChatGPTLogin(ctx context.Context, cfg Config, code, verifier string) error {
	pinned := cfg.Grant == GrantChatGPT && cfg.TokenURL == ChatGPTTokenURL && cfg.ClientID == ChatGPTClientID && cfg.AuthorizeURL == ChatGPTAuthorizeURL && cfg.RedirectURI == ChatGPTRedirectURI
	return m.completeLogin(ctx, cfg, pinned, func(ctx context.Context, client httpDoer) (Tokens, error) {
		form := url.Values{"grant_type": {"authorization_code"}, "client_id": {ChatGPTClientID}, "code": {code}, "redirect_uri": {ChatGPTRedirectURI}, "code_verifier": {verifier}}
		return chatGPTTokenRequest(ctx, client, form, "")
	})
}

func (m *Manager) CompleteAnthropicLogin(ctx context.Context, cfg Config, code, state, verifier string) error {
	pinned := cfg.Grant == GrantAnthropic && AnthropicPinned(cfg)
	return m.completeLogin(ctx, cfg, pinned, func(ctx context.Context, client httpDoer) (Tokens, error) {
		return ExchangeAnthropicCode(ctx, client, code, state, verifier)
	})
}

func (m *Manager) completeLogin(ctx context.Context, cfg Config, pinned bool, exchange func(context.Context, httpDoer) (Tokens, error)) error {
	if err := m.begin(); err != nil {
		return err
	}
	defer m.work.Done()
	m.loginMu.Lock()
	reserved := m.logins[cfg.Name]
	m.loginMu.Unlock()
	if !reserved || !pinned {
		return ErrOperationBusy
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	defer cancel()
	client, err := m.mintClient()
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		if m.closing() {
			return ErrStopped
		}
		return err
	}
	tok, err := exchange(ctx, client)
	if err != nil {
		if m.closing() {
			m.uncertain()
			return ErrStopped
		}
		return err
	}
	grant, err := grantFor(cfg)
	if err != nil {
		return err
	}
	if err = grant.Validate(cfg, tok); err != nil {
		return err
	}
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	if !m.logins[cfg.Name] {
		return ErrOperationBusy
	}
	state := newTokenState(tok, "", m.now())
	if err = m.saveFile(cfg, state); err != nil {
		m.uncertain()
		return ErrDrainUncertain
	}
	m.installState(cfg, state)
	return nil
}
