package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/jack-work/hush/identity"
	"github.com/jack-work/hush/oauth"
	"github.com/jack-work/hush/secrets"
	"github.com/jack-work/hush/version"
)

// Agent holds the decrypted identity and manages the unix socket listener.
type Agent struct {
	id         *identity.DecryptedIdentity
	listener   net.Listener
	ttl        time.Duration
	deadline   time.Time
	runtimeDir string
	stateDir   string
	oauth      *oauth.Manager
	log        *log.Logger

	// lockFile holds the single-instance flock for the agent's lifetime.
	// Non-nil iff this process owns the runtime directory's files.
	lockFile *os.File
}

// New creates an agent from an already-decrypted identity. stateDir is used
// for persistent state owned by the agent (currently: OAuth credentials).
func New(id *identity.DecryptedIdentity, ttl time.Duration, runtimeDir, stateDir string, logger *log.Logger) *Agent {
	a := &Agent{
		id:         id,
		ttl:        ttl,
		runtimeDir: runtimeDir,
		stateDir:   stateDir,
		log:        logger,
	}
	if rec := firstX25519Recipient(id.Identities); rec != nil {
		a.oauth = oauth.NewManager(stateDir, id.Identities, rec, logger)
	} else {
		logger.Printf("warning: no X25519 identity available; OAuth credential management disabled")
	}
	return a
}

// Run starts the agent: takes the single-instance lock, listens on the
// socket, and blocks until TTL expires or a signal is received. The
// identity is zeroed on exit.
func (a *Agent) Run() error {
	defer a.shutdown()

	if err := os.MkdirAll(a.runtimeDir, 0700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}

	if err := a.acquireLock(); err != nil {
		return err
	}

	// We hold the lock, so no other agent is alive: any leftover socket
	// is stale (e.g. a SIGKILL'd predecessor) and safe to replace.
	os.Remove(a.sockPath())

	if a.oauth != nil {
		if err := a.oauth.Start(); err != nil {
			a.log.Printf("oauth: start failed: %v", err)
		}
	}

	sockPath := a.sockPath()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	a.listener = ln

	if err := os.Chmod(sockPath, 0600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	a.deadline = time.Now().Add(a.ttl)
	a.log.Printf("agent started, pid=%d, ttl=%s, deadline=%s",
		os.Getpid(), a.ttl, a.deadline.Format(time.RFC3339))

	// TTL timer.
	ttlTimer := time.AfterFunc(a.ttl, func() {
		a.log.Printf("TTL expired, shutting down")
		a.listener.Close()
	})
	defer ttlTimer.Stop()

	// Signal handler.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		a.log.Printf("received %s, shutting down", sig)
		a.listener.Close()
	}()

	// Accept loop — goroutine per connection.
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			// Listener closed by TTL timer or signal handler.
			if isClosedErr(err) {
				return nil
			}
			a.log.Printf("accept error: %v", err)
			continue
		}
		go a.handleConn(conn)
	}
}

func (a *Agent) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		conn.Write(errResponse("invalid request: " + err.Error()))
		return
	}

	var resp []byte
	switch req.Op {
	case "decrypt":
		resp = a.handleDecrypt(req)
	case "encrypt":
		resp = a.handleEncrypt(req)
	case "status":
		resp = a.handleStatus()
	case "version":
		resp = a.handleVersion()
	case "oauth_register":
		resp = a.handleOAuthRegister(req)
	case "oauth_get":
		resp = a.handleOAuthGet(req)
	case "oauth_refresh":
		resp = a.handleOAuthRefresh(req)
	case "oauth_delete":
		resp = a.handleOAuthDelete(req)
	case "oauth_list":
		resp = a.handleOAuthList()
	default:
		resp = errResponse(fmt.Sprintf("unknown op: %q", req.Op))
	}

	conn.Write(resp)
	conn.Write([]byte("\n"))
}

func (a *Agent) handleDecrypt(req Request) []byte {
	out := make(map[string]string, len(req.Values))
	for k, v := range req.Values {
		if secrets.IsEncrypted(v) {
			dec, err := secrets.DecryptValue(v, a.id.Identities)
			if err != nil {
				return errResponse(fmt.Sprintf("decrypt %q: %v", k, err))
			}
			out[k] = dec
		} else {
			out[k] = v
		}
	}
	return okResponse(Response{Values: out})
}

func (a *Agent) handleEncrypt(req Request) []byte {
	recipient, err := a.recipient()
	if err != nil {
		return errResponse(err.Error())
	}

	out := make(map[string]string, len(req.Values))
	for k, v := range req.Values {
		if secrets.IsEncrypted(v) {
			// Already encrypted, pass through.
			out[k] = v
		} else {
			enc, err := secrets.EncryptValue(v, recipient)
			if err != nil {
				return errResponse(fmt.Sprintf("encrypt %q: %v", k, err))
			}
			out[k] = enc
		}
	}
	return okResponse(Response{Values: out})
}

func (a *Agent) handleOAuthRegister(req Request) []byte {
	if a.oauth == nil {
		return errResponse("oauth: no X25519 identity available")
	}
	if req.OAuth == nil {
		return errResponseCoded("oauth: missing oauth payload", ErrCodeOAuthBadRequest)
	}
	o := req.OAuth
	err := a.oauth.Register(oauth.Config{
		Name:         o.Name,
		AuthorizeURL: o.AuthorizeURL,
		TokenURL:     o.TokenURL,
		RedirectURI:  o.RedirectURI,
		ClientID:     o.ClientID,
		Scopes:       o.Scopes,
	}, oauth.Tokens{
		AccessToken:  o.AccessToken,
		RefreshToken: o.RefreshToken,
		ExpiresIn:    o.ExpiresIn,
	})
	if err != nil {
		return errResponseCoded(err.Error(), ErrCodeOAuthBadRequest)
	}
	return okResponse(Response{})
}

func (a *Agent) handleOAuthGet(req Request) []byte {
	if a.oauth == nil {
		return errResponse("oauth: no X25519 identity available")
	}
	if req.OAuth == nil || req.OAuth.Name == "" {
		return errResponseCoded("oauth: name required", ErrCodeOAuthBadRequest)
	}
	tok, err := a.oauth.Get(req.OAuth.Name)
	if err != nil {
		return errResponseCoded(err.Error(), oauthErrCode(err))
	}
	return okResponse(Response{Token: tok})
}

func (a *Agent) handleOAuthRefresh(req Request) []byte {
	if a.oauth == nil {
		return errResponse("oauth: no X25519 identity available")
	}
	if req.OAuth == nil || req.OAuth.Name == "" {
		return errResponseCoded("oauth: name required", ErrCodeOAuthBadRequest)
	}
	tok, err := a.oauth.Refresh(req.OAuth.Name)
	if err != nil {
		return errResponseCoded(err.Error(), oauthErrCode(err))
	}
	return okResponse(Response{Token: tok})
}

func (a *Agent) handleOAuthDelete(req Request) []byte {
	if a.oauth == nil {
		return errResponse("oauth: no X25519 identity available")
	}
	if req.OAuth == nil || req.OAuth.Name == "" {
		return errResponseCoded("oauth: name required", ErrCodeOAuthBadRequest)
	}
	if err := a.oauth.Delete(req.OAuth.Name); err != nil {
		return errResponse(err.Error())
	}
	return okResponse(Response{})
}

func (a *Agent) handleOAuthList() []byte {
	if a.oauth == nil {
		return errResponse("oauth: no X25519 identity available")
	}
	return okResponse(Response{Names: a.oauth.List()})
}

func oauthErrCode(err error) string {
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		return ErrCodeOAuthNotFound
	case errors.Is(err, oauth.ErrRefreshPermanent):
		return ErrCodeOAuthRefreshPermanent
	case errors.Is(err, oauth.ErrRefreshTransient):
		return ErrCodeOAuthRefreshTransient
	default:
		return ""
	}
}

// recipient derives the public key from the first X25519 identity.
func (a *Agent) recipient() (age.Recipient, error) {
	r := firstX25519Recipient(a.id.Identities)
	if r == nil {
		return nil, fmt.Errorf("no X25519 identity available for encryption")
	}
	return r, nil
}

func firstX25519Recipient(ids []age.Identity) age.Recipient {
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x.Recipient()
		}
	}
	return nil
}

func (a *Agent) handleVersion() []byte {
	return okResponse(Response{Version: version.Version})
}

func (a *Agent) handleStatus() []byte {
	remaining := time.Until(a.deadline).Truncate(time.Second)
	if remaining < 0 {
		remaining = 0
	}
	return okResponse(Response{TTLRemaining: remaining.String()})
}

func (a *Agent) shutdown() {
	if a.oauth != nil {
		a.oauth.Stop()
	}
	a.log.Printf("zeroing identity")
	a.id.Zero()

	// Only the lock holder owns the runtime files. A Run that failed to
	// acquire the lock must not touch the live agent's socket.
	if a.lockFile != nil {
		os.Remove(a.sockPath())
		// Release the lock last; the PID file itself stays in place —
		// it is the lock inode (see acquireLock).
		a.lockFile.Close()
		a.lockFile = nil
	}
	a.log.Printf("agent stopped")
}

func (a *Agent) sockPath() string {
	return filepath.Join(a.runtimeDir, "agent.sock")
}

func (a *Agent) pidPath() string {
	return filepath.Join(a.runtimeDir, "agent.pid")
}

// acquireLock takes the single-instance lock: an exclusive flock(2) on the
// PID file, held for the agent's lifetime. Acquiring the lock *is* the
// claim — there is no window between checking for a live agent and
// becoming one. The kernel releases the lock when the process exits,
// however it exits, so there is no stale state to detect or clean up.
//
// The PID file is never unlinked, by anyone: flock attaches to the inode,
// so removing the file would let a second agent lock a fresh inode at the
// same path while the first still holds the old one. Its content (our pid)
// is informational, for `hush down` and humans.
func (a *Agent) acquireLock() error {
	f, err := os.OpenFile(a.pidPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		data, _ := io.ReadAll(f)
		f.Close()
		holder := strings.TrimSpace(string(data))
		if holder == "" {
			holder = "unknown pid"
		} else {
			holder = "pid " + holder
		}
		return fmt.Errorf("agent already running (%s holds %s)", holder, a.pidPath())
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return fmt.Errorf("truncate lock file: %w", err)
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		f.Close()
		return fmt.Errorf("write pid: %w", err)
	}
	a.lockFile = f
	return nil
}

func isClosedErr(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), io.ErrClosedPipe.Error())
}
