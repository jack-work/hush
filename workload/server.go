package workload

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/ca"
	"github.com/jack-work/hush/spiffeid"
)

type Authority struct {
	Intermediate     crypto.Signer
	IntermediateCert *x509.Certificate
	JWTKey           *ecdsa.PrivateKey
	JWTKeyID         string
	Bundle           *bundle.Bundle
}

type Server struct {
	Attest Attestor
	Policy Policy
	Now    func() time.Time
	Log    *slog.Logger
	// Creds names JWT-SVIDs a credential-socket client can fetch: GET
	// /cred/<name> answers the CALLER's own JWT-SVID for that name's
	// audiences, in hush cred serve's response shape.
	Creds map[string][]string

	mu   sync.RWMutex
	auth Authority
}

func NewServer(attest Attestor, policy Policy, auth Authority) *Server {
	return &Server{Attest: attest, Policy: policy, Now: time.Now, Log: slog.Default(), auth: auth}
}

func (s *Server) SetAuthority(a Authority) {
	s.mu.Lock()
	s.auth = a
	s.mu.Unlock()
}

func (s *Server) authority() Authority {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auth
}

type connKey struct{}

func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/x509-svid", s.x509)
	mux.HandleFunc("POST /v1/jwt-svid", s.jwt)
	mux.HandleFunc("GET /v1/bundle", s.bundle)
	mux.HandleFunc("GET /cred/{name}", s.cred)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ConnContext:       func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, connKey{}, c) },
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type apiError struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

func fail(w http.ResponseWriter, status int, code, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiError{code, reason})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) identify(w http.ResponseWriter, r *http.Request) (spiffeid.ID, bool) {
	conn, _ := r.Context().Value(connKey{}).(net.Conn)
	if conn == nil {
		fail(w, http.StatusForbidden, "unattested", "no connection")
		return spiffeid.ID{}, false
	}
	peer, err := s.Attest(conn)
	if err != nil {
		s.Log.Info("workload refused", "reason", err.Error())
		fail(w, http.StatusForbidden, "unattested", err.Error())
		return spiffeid.ID{}, false
	}
	id, err := s.Policy(peer)
	if err != nil {
		s.Log.Info("workload refused", "pid", peer.PID, "uid", peer.UID, "cgroup", peer.Cgroup, "reason", err.Error())
		fail(w, http.StatusForbidden, "unattested", err.Error())
		return spiffeid.ID{}, false
	}
	return id, true
}

type X509Request struct {
	CSR string `json:"csr"`
}

type X509Response struct {
	SPIFFEID   string    `json:"spiffe_id"`
	Chain      string    `json:"chain"`
	ExpiresAt  time.Time `json:"expires_at"`
	RenewAfter time.Time `json:"renew_after"`
}

func (s *Server) x509(w http.ResponseWriter, r *http.Request) {
	id, ok := s.identify(w, r)
	if !ok {
		return
	}
	var req X509Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		fail(w, http.StatusBadRequest, "bad_request", "want a PEM CERTIFICATE REQUEST")
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "csr: "+err.Error())
		return
	}
	a := s.authority()
	if a.Intermediate == nil || a.IntermediateCert == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "no intermediate")
		return
	}
	now := s.Now()
	leaf, err := ca.IssueX509SVID(a.Intermediate, a.IntermediateCert, id, csr.PublicKey, now, 0)
	if errors.Is(err, ca.ErrIssuerExpired) {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	if errors.Is(err, ca.ErrOutsideNode) {
		fail(w, http.StatusForbidden, "not_granted", err.Error())
		return
	}
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	s.Log.Info("x509-svid issued", "spiffe_id", id.String(), "serial", leaf.SerialNumber.Text(16), "expires", leaf.NotAfter)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.IntermediateCert.Raw})...)
	life := leaf.NotAfter.Sub(now)
	reply(w, X509Response{SPIFFEID: id.String(), Chain: string(chain), ExpiresAt: leaf.NotAfter, RenewAfter: now.Add(life * 2 / 3)})
}

type JWTRequest struct {
	Audience []string `json:"audience"`
}

type JWTResponse struct {
	SPIFFEID  string    `json:"spiffe_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) jwt(w http.ResponseWriter, r *http.Request) {
	id, ok := s.identify(w, r)
	if !ok {
		return
	}
	var req JWTRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if tok, exp, ok := s.issueJWT(w, id, req.Audience); ok {
		reply(w, JWTResponse{SPIFFEID: id.String(), Token: tok, ExpiresAt: exp})
	}
}

func (s *Server) issueJWT(w http.ResponseWriter, id spiffeid.ID, audience []string) (string, time.Time, bool) {
	a := s.authority()
	if a.JWTKey == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "no jwt key")
		return "", time.Time{}, false
	}
	tok, exp, err := ca.IssueJWTSVID(a.JWTKey, a.JWTKeyID, id, audience, s.Now(), 0)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return "", time.Time{}, false
	}
	s.Log.Info("jwt-svid issued", "spiffe_id", id.String(), "audience", fmt.Sprint(audience), "expires", exp)
	return tok, exp, true
}

// ParseCreds reads name=aud[,aud] rows for Server.Creds.
func ParseCreds(raw []string) (map[string][]string, error) {
	rows := map[string][]string{}
	for _, r := range raw {
		name, auds, ok := strings.Cut(r, "=")
		list := strings.Split(auds, ",")
		if !ok || name == "" || slices.Contains(list, "") {
			return nil, fmt.Errorf("cred %q: want name=aud[,aud]", r)
		}
		if _, dup := rows[name]; dup {
			return nil, fmt.Errorf("cred %s given twice", name)
		}
		rows[name] = list
	}
	return rows, nil
}

// CredResponse is hush cred serve's answer, so a [cred] client reads either.
type CredResponse struct {
	Name      string `json:"name"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// cred answers GET /cred/<name>[?audience=a]: the caller's own JWT-SVID for
// the name's audiences, or for the ones it asks for if all are among them.
func (s *Server) cred(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	allowed, ok := s.Creds[name]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no cred "+name)
		return
	}
	audience := allowed
	if asked := r.URL.Query()["audience"]; len(asked) > 0 {
		for _, a := range asked {
			if !slices.Contains(allowed, a) {
				fail(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("audience %q is not %s's", a, name))
				return
			}
		}
		audience = asked
	}
	id, ok := s.identify(w, r)
	if !ok {
		return
	}
	if tok, exp, ok := s.issueJWT(w, id, audience); ok {
		reply(w, CredResponse{Name: name, Token: tok, ExpiresAt: exp.Unix()})
	}
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.identify(w, r); !ok {
		return
	}
	a := s.authority()
	if a.Bundle == nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", "no bundle")
		return
	}
	raw, err := a.Bundle.Marshal()
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
