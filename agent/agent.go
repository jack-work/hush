package agent

import (
	"encoding/json"
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

	"github.com/jack-work/hush/identity"
	"github.com/jack-work/hush/secrets"
)

// Agent holds the decrypted identity and manages the unix socket listener.
type Agent struct {
	id         *identity.DecryptedIdentity
	listener   net.Listener
	ttl        time.Duration
	deadline   time.Time
	runtimeDir string
	log        *log.Logger
}

// New creates an agent from an already-decrypted identity.
func New(id *identity.DecryptedIdentity, ttl time.Duration, runtimeDir string, logger *log.Logger) *Agent {
	return &Agent{
		id:         id,
		ttl:        ttl,
		runtimeDir: runtimeDir,
		log:        logger,
	}
}

// Run starts the agent: writes PID file, listens on the socket, and blocks
// until TTL expires or a signal is received. The identity is zeroed on exit.
func (a *Agent) Run() error {
	defer a.shutdown()

	if err := os.MkdirAll(a.runtimeDir, 0700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}

	if err := a.checkStale(); err != nil {
		return err
	}

	if err := a.writePID(); err != nil {
		return err
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
	case "status":
		resp = a.handleStatus()
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

func (a *Agent) handleStatus() []byte {
	remaining := time.Until(a.deadline).Truncate(time.Second)
	if remaining < 0 {
		remaining = 0
	}
	return okResponse(Response{TTLRemaining: remaining.String()})
}

func (a *Agent) shutdown() {
	a.log.Printf("zeroing identity")
	a.id.Zero()

	os.Remove(a.sockPath())
	os.Remove(a.pidPath())
	a.log.Printf("agent stopped")
}

func (a *Agent) sockPath() string {
	return filepath.Join(a.runtimeDir, "agent.sock")
}

func (a *Agent) pidPath() string {
	return filepath.Join(a.runtimeDir, "agent.pid")
}

func (a *Agent) writePID() error {
	return os.WriteFile(a.pidPath(), []byte(strconv.Itoa(os.Getpid())), 0600)
}

// checkStale detects whether an agent is already running. If a stale socket
// or PID file exists, it cleans them up. If a live agent is found, returns
// an error so the caller can exit.
func (a *Agent) checkStale() error {
	sockPath := a.sockPath()

	// Try connecting to existing socket.
	if conn, err := net.DialTimeout("unix", sockPath, time.Second); err == nil {
		conn.Close()
		return fmt.Errorf("agent already running (socket %s responds)", sockPath)
	}

	// Socket exists but nobody's home — remove it.
	os.Remove(sockPath)

	// Check PID file.
	pidPath := a.pidPath()
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return nil // no PID file, all clear
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		os.Remove(pidPath)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidPath)
		return nil
	}

	// Signal 0 checks if process exists without actually signaling it.
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		return fmt.Errorf("agent already running (pid %d)", pid)
	}

	// Stale PID file — remove it.
	a.log.Printf("removing stale pid file (pid %d)", pid)
	os.Remove(pidPath)
	return nil
}

func isClosedErr(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), io.ErrClosedPipe.Error())
}
