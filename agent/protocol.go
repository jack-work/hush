package agent

import "encoding/json"

// Request is the JSON envelope sent by clients over the unix socket.
type Request struct {
	Op string `json:"op"`

	// Used by encrypt/decrypt.
	Values map[string]string `json:"values,omitempty"`

	// Used by oauth_* ops.
	OAuth *OAuthRequest `json:"oauth,omitempty"`
}

// OAuthRequest carries the fields for any oauth_* op. Which subset is
// required depends on Op:
//   oauth_register:  Name, AuthorizeURL, TokenURL, RedirectURI, ClientID,
//                    Scopes, AccessToken, RefreshToken, ExpiresIn
//   oauth_get:       Name
//   oauth_refresh:   Name
//   oauth_delete:    Name
//   oauth_list:      (none)
type OAuthRequest struct {
	Name         string `json:"name,omitempty"`
	AuthorizeURL string `json:"authorize_url,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// Response is the JSON envelope returned by the agent.
type Response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`

	Values       map[string]string `json:"values,omitempty"`        // decrypt/encrypt
	TTLRemaining string            `json:"ttl_remaining,omitempty"` // status
	Version      string            `json:"version,omitempty"`       // version

	Token string   `json:"token,omitempty"` // oauth_get, oauth_refresh
	Names []string `json:"names,omitempty"` // oauth_list
}

// Structured error codes returned in Response.ErrorCode.
const (
	ErrCodeOAuthNotFound         = "oauth_not_found"
	ErrCodeOAuthRefreshPermanent = "oauth_refresh_permanent"
	ErrCodeOAuthRefreshTransient = "oauth_refresh_transient"
	ErrCodeOAuthBadRequest       = "oauth_bad_request"
)

func errResponse(msg string) []byte {
	b, _ := json.Marshal(Response{OK: false, Error: msg})
	return b
}

func errResponseCoded(msg, code string) []byte {
	b, _ := json.Marshal(Response{OK: false, Error: msg, ErrorCode: code})
	return b
}

func okResponse(r Response) []byte {
	r.OK = true
	b, _ := json.Marshal(r)
	return b
}
