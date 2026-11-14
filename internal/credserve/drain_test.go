//go:build linux

package credserve

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jack-work/hush/internal/oauth"
)

type drainRoundTrip func(*http.Request) (*http.Response, error)

func (f drainRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func drainConfig(key *age.X25519Recipient) *Config {
	return &Config{Recipient: key.String(), AllowUser: fmt.Sprint(os.Getuid()), recipient: key, Instances: map[string]Instance{instName: {Kind: KindAnthropic, TokenURL: "https://fake.invalid/token", AuthorizeURL: "https://fake.invalid/auth", RedirectURI: "https://fake.invalid/callback", ClientID: "fake-drain"}}}
}

func drainChild() int {
	dir := os.Getenv("HUSH_FAKE_DRAIN_DIR")
	mode := os.Getenv("HUSH_FAKE_DRAIN_MODE")
	input := bufio.NewReader(os.Stdin)
	line, err := input.ReadString('\n')
	if err != nil {
		return 3
	}
	key, err := age.ParseX25519Identity(strings.TrimSpace(line))
	if err != nil {
		return 4
	}
	owner, err := LockState(dir)
	if err != nil {
		return 5
	}
	defer owner.Close()
	var outputMu sync.Mutex
	phase := func(name, state string) {
		outputMu.Lock()
		defer outputMu.Unlock()
		json.NewEncoder(os.Stdout).Encode(map[string]string{"phase": name, "state": state})
	}
	cfg := drainConfig(key.Recipient())
	manager := oauth.NewManager(dir, []age.Identity{key}, key.Recipient(), log.New(io.Discard, "", 0))
	manager.SetHTTPClient(&http.Client{Transport: drainRoundTrip(func(req *http.Request) (*http.Response, error) {
		phase("refresh_entered", "")
		<-req.Context().Done()
		phase("refresh_cancelled", "")
		control, err := input.ReadString('\n')
		if err != nil || control != "release\n" {
			return nil, errors.New("fake response unavailable")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"access_token":"A2","refresh_token":"R2","expires_in":3600}`)), Request: req}, nil
	})})
	if err := manager.Start(); err != nil {
		return 6
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "cred.sock"))
	if err != nil {
		return 7
	}
	server := NewServer(cfg, manager, uint32(os.Getuid()), log.New(io.Discard, "", 0))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	observer := make(chan struct{})
	go func() {
		<-ctx.Done()
		err := manager.Stop()
		state := "clean"
		if err != nil {
			state = "uncertain"
		}
		phase("manager_drained", state)
		close(observer)
	}()
	phase("ready", "")
	serveErr := server.ServeContext(ctx, listener)
	<-observer
	if err := owner.Close(); err != nil {
		return 8
	}
	state := "clean"
	code := 0
	if serveErr != nil {
		state = "uncertain"
		code = 2
	}
	phase("owner_released", state)
	if mode == "persist-fail" && serveErr != oauth.ErrDrainUncertain {
		return 9
	}
	return code
}

func TestChildOwnerLockHeldUntilManagerAndHTTPDrain(t *testing.T) {
	if os.Getenv("HUSH_FAKE_DRAIN_DIR") != "" {
		os.Exit(drainChild())
	}
	for _, mode := range []string{"success", "persist-fail"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			key, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			cfg := drainConfig(key.Recipient())
			seed := oauth.NewManager(dir, []age.Identity{key}, key.Recipient(), log.New(io.Discard, "", 0))
			if err := seed.Register(cfg.Instances[instName].OAuthConfig(instName), oauth.Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
				t.Fatal(err)
			}
			if err := seed.Stop(); err != nil {
				t.Fatal(err)
			}
			deadline, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(deadline, os.Args[0], "-test.run=^TestChildOwnerLockHeldUntilManagerAndHTTPDrain$")
			cmd.Env = []string{"HUSH_FAKE_DRAIN_DIR=" + dir, "HUSH_FAKE_DRAIN_MODE=" + mode, "GOTRACEBACK=none", "PATH=/usr/bin:/bin"}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
			fmt.Fprintln(stdin, key.String())
			reader := bufio.NewReader(stdout)
			phase := func(want string) string {
				t.Helper()
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatal("fake owner phase missing")
				}
				var doc map[string]string
				if json.Unmarshal([]byte(line), &doc) != nil || doc["phase"] != want {
					t.Fatal("unexpected fake owner phase")
				}
				return doc["state"]
			}
			phase("ready")
			idle, err := net.Dial("unix", filepath.Join(dir, "cred.sock"))
			if err != nil {
				t.Fatal(err)
			}
			defer idle.Close()
			io.WriteString(idle, "GET /cred/anthropic-work HTTP/1.1\r\nHost: minter\r\n")
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "cred.sock"))
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			requestDone := make(chan struct{})
			go func() {
				defer close(requestDone)
				req, _ := http.NewRequest("POST", "http://minter/refresh/"+instName, nil)
				response, err := client.Do(req)
				if err == nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
			}()
			phase("refresh_entered")
			if mode == "persist-fail" {
				if err := os.Rename(filepath.Join(dir, "oauth"), filepath.Join(dir, "saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "oauth"), []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			phase("refresh_cancelled")
			if lock, err := LockState(dir); err == nil {
				lock.Close()
				t.Fatal("owner lock released while valid response was still pending")
			}
			fmt.Fprintln(stdin, "release")
			state := phase("manager_drained")
			if (mode == "success" && state != "clean") || (mode == "persist-fail" && state != "uncertain") {
				t.Fatal("manager drain status was fabricated")
			}
			if lock, err := LockState(dir); err == nil {
				lock.Close()
				t.Fatal("owner lock released while HTTP connection worker remained active")
			}
			idle.Close()
			<-requestDone
			state = phase("owner_released")
			waitErr := cmd.Wait()
			if mode == "success" {
				if waitErr != nil || state != "clean" {
					t.Fatal("fake successful drain did not exit cleanly")
				}
			} else {
				var exit *exec.ExitError
				if !errors.As(waitErr, &exit) || exit.ExitCode() != 2 || state != "uncertain" {
					t.Fatal("uncertain drain was reported as process success")
				}
			}
			lock, err := LockState(dir)
			if err != nil {
				t.Fatal("owner lock remained held after completed drain")
			}
			lock.Close()
			if mode == "success" {
				next := oauth.NewManager(dir, []age.Identity{key}, key.Recipient(), log.New(io.Discard, "", 0))
				defer next.Stop()
				if err := next.Adopt(instName); err != nil {
					t.Fatal(err)
				}
				lease, err := next.Lease(instName)
				if err != nil || lease.AccessToken != "A2" {
					t.Fatal("fully committed fake successor was lost at drain")
				}
			}
		})
	}
}

func TestStoppedMinterIsNotAReLoginInstruction(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	if err := r.mgr.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, methodPath := range [][2]string{{"GET", "/cred/" + instName}, {"POST", "/refresh/" + instName}} {
		req, _ := http.NewRequest(methodPath[0], "http://minter"+methodPath[1], nil)
		response, err := r.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 503 || !strings.Contains(string(raw), "manager_stopped") || strings.Contains(string(raw), "sign-in needed") || strings.Contains(string(raw), "at-seed") {
			t.Fatal("stopped manager was mislabeled or served a token")
		}
	}
}
