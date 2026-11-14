package oauth

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
)

func TestCrashAfterProviderRotationBeforeResponseRemainsAnExplicitGap(t *testing.T) {
	if dir := os.Getenv("HUSH_DRAIN_FAKE_CRASH_DIR"); dir != "" {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			os.Exit(3)
		}
		key, err := age.ParseX25519Identity(strings.TrimSpace(line))
		if err != nil {
			os.Exit(4)
		}
		cert, err := os.ReadFile(os.Getenv("HUSH_DRAIN_FAKE_CA"))
		if err != nil {
			os.Exit(5)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cert) {
			os.Exit(6)
		}
		manager := NewManager(dir, []age.Identity{key}, key.Recipient(), log.New(io.Discard, "", 0))
		manager.SetHTTPClient(&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}})
		if manager.Adopt(testCfg.Name) != nil {
			os.Exit(7)
		}
		manager.Refresh(testCfg.Name)
		os.Exit(8)
	}
	dir, key := t.TempDir(), newTestKey(t)
	accepted := make(chan struct{})
	var rotations atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("refresh_token") != "R1" {
			t.Error("unexpected fake predecessor")
		}
		rotations.Add(1)
		close(accepted)
		<-r.Context().Done()
	}))
	defer server.Close()
	cfg := testCfg
	cfg.TokenURL = server.URL
	seed := newTestManager(t, dir, key)
	if err := seed.Register(cfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	seed.Stop()
	ca := filepath.Join(dir, "fake-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashAfterProviderRotationBeforeResponseRemainsAnExplicitGap$")
	cmd.Env = []string{"HUSH_DRAIN_FAKE_CRASH_DIR=" + dir, "HUSH_DRAIN_FAKE_CA=" + ca, "GOTRACEBACK=none", "PATH=/usr/bin:/bin"}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	fmt.Fprintln(input, key.String())
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("fake provider never accepted rotation")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("crash was reported as graceful drain")
	}
	_, disk, _, err := seed.loadFile(seed.filePath(cfg.Name))
	if err != nil || disk.refresh != "R1" || disk.relogin != "" || rotations.Load() != 1 {
		t.Fatal("unknown response fabricated recovery or a new login requirement")
	}
}
