package credserve

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

type loginCallback struct {
	code string
	err  error
}

func (l *Login) chatGPT(ctx context.Context, in Instance) (oauth.Tokens, error) {
	if err := in.validate(l.Name); err != nil {
		return oauth.Tokens{}, err
	}
	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		return oauth.Tokens{}, err
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return oauth.Tokens{}, err
	}
	state := base64.RawURLEncoding.EncodeToString(random)
	listen := l.Listen
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", "127.0.0.1:1455")
	if err != nil {
		return oauth.Tokens{}, errors.New("ChatGPT callback port 1455 unavailable")
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	results := make(chan loginCallback, 1)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, ErrorLog: discardLogger(), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet || r.URL.Path != "/auth/callback" || r.Host != "localhost:1455" {
			http.Error(w, "invalid callback", 400)
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "invalid state", 400)
			select {
			case results <- loginCallback{err: errors.New("ChatGPT callback state mismatch")}:
			default:
			}
			return
		}
		if q.Get("error") != "" || len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > 8192 {
			http.Error(w, "login refused", 400)
			select {
			case results <- loginCallback{err: errors.New("ChatGPT authorization refused")}:
			default:
			}
			return
		}
		select {
		case results <- loginCallback{code: q.Get("code")}:
			fmt.Fprintln(w, "Login received. You can close this window.")
		default:
			http.Error(w, "callback already received", 409)
		}
	})}
	defer srv.Close()
	go srv.Serve(ln)
	q := url.Values{"client_id": {oauth.ChatGPTClientID}, "redirect_uri": {oauth.ChatGPTRedirectURI}, "response_type": {"code"}, "scope": {oauth.ChatGPTScopes}, "code_challenge": {pkce.Challenge}, "code_challenge_method": {"S256"}, "state": {state}, "id_token_add_organizations": {"true"}, "codex_cli_simplified_flow": {"true"}, "originator": {"codex_cli_rs"}}
	fmt.Fprintf(l.Out, "Open this URL for a fresh ChatGPT login:\n\n%s?%s\n\n", oauth.ChatGPTAuthorizeURL, q.Encode())
	var result loginCallback
	select {
	case result = <-results:
	case <-ctx.Done():
		return oauth.Tokens{}, errors.New("ChatGPT login cancelled or timed out")
	}
	if result.err != nil {
		return oauth.Tokens{}, result.err
	}
	return oauth.ExchangeChatGPTCode(ctx, l.Client, result.code, pkce.Verifier)
}
