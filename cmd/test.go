package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/gluck/hush/agent"
	"github.com/gluck/hush/identity"
	"github.com/gluck/hush/secrets"
)

func init() {
	rootCmd.AddCommand(testCmd)
}

var testCmd = &cobra.Command{
	Use:    "test",
	Short:  "Run integration test",
	Hidden: true,
	RunE:   runTest,
}

func runTest(cmd *cobra.Command, args []string) error {
	dir, err := os.MkdirTemp("", "hush-test-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// --- Config ---
	fmt.Println("=== Config ===")
	fmt.Printf("  TTL:         %s\n", cfg.TTL)
	fmt.Printf("  Identity:    %s\n", cfg.IdentityFile)
	fmt.Printf("  ConfigDir:   %s\n", cfg.ConfigDir)
	fmt.Printf("  CommandsDir: %s\n", cfg.CommandsDir)
	fmt.Printf("  RuntimeDir:  %s\n", cfg.RuntimeDir)

	// --- Identity ---
	fmt.Println("\n=== Identity ===")
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	fmt.Printf("  Generated pubkey: %s\n", ageID.Recipient())

	keyData := []byte(ageID.String() + "\n")
	keyFile := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		return err
	}

	id, err := identity.UnlockPlaintext(keyFile)
	if err != nil {
		return err
	}
	defer id.Zero()
	fmt.Printf("  Loaded %d identity(ies) from plaintext\n", len(id.Identities))

	encKeyFile := filepath.Join(dir, "identity.age")
	if err := identity.EncryptToFile(keyData, encKeyFile, "testpass"); err != nil {
		return err
	}
	passID, err := identity.Unlock(encKeyFile, []byte("testpass"))
	if err != nil {
		return err
	}
	defer passID.Zero()
	fmt.Printf("  Loaded %d identity(ies) from encrypted file\n", len(passID.Identities))

	// --- Secrets ---
	fmt.Println("\n=== Secrets ===")
	original := map[string]string{
		"token":     "super-secret-token-123",
		"api_key":   "sk-abc-456",
		"client_id": "not-secret-plaintext",
	}

	tomlBytes, err := secrets.EncryptFile(original, ageID.Recipient(), []string{"token", "api_key"})
	if err != nil {
		return err
	}

	secretsPath := filepath.Join(dir, "secrets.toml")
	if err := os.WriteFile(secretsPath, tomlBytes, 0600); err != nil {
		return err
	}

	fmt.Println("  On-disk secrets.toml:")
	for _, line := range strings.Split(string(tomlBytes), "\n") {
		if line != "" {
			fmt.Printf("    %s\n", line)
		}
	}

	decrypted, err := secrets.DecryptFile(secretsPath, id.Identities)
	if err != nil {
		return err
	}
	fmt.Println("\n  Decrypted:")
	for k, orig := range original {
		fmt.Printf("    %s %s = %q\n", check(decrypted[k] == orig), k, decrypted[k])
	}

	// --- encrypt-value round-trip ---
	fmt.Println("\n=== encrypt-value ===")
	testPlain := "round-trip-test-value"
	enc, err := secrets.EncryptValue(testPlain, ageID.Recipient())
	if err != nil {
		return err
	}
	fmt.Printf("  Encrypted: %s...]\n", enc[:40])
	dec, err := secrets.DecryptValue(enc, id.Identities)
	if err != nil {
		return err
	}
	fmt.Printf("  %s round-trip = %q\n", check(dec == testPlain), dec)

	// --- Agent ---
	fmt.Println("\n=== Agent ===")
	runtimeDir := filepath.Join(dir, "runtime")
	logger := log.New(io.Discard, "", 0)

	ag := agent.New(id, 30*time.Second, runtimeDir, logger)
	agentDone := make(chan error, 1)
	go func() { agentDone <- ag.Run() }()

	sockPath := filepath.Join(runtimeDir, "agent.sock")
	if err := waitForSocket(sockPath, 2*time.Second); err != nil {
		return fmt.Errorf("agent didn't start: %w", err)
	}
	fmt.Println("  Agent listening")

	var rawValues map[string]string
	if err := toml.Unmarshal(tomlBytes, &rawValues); err != nil {
		return err
	}

	resp, err := testRPC(sockPath, agent.Request{Op: "decrypt", Values: rawValues})
	if err != nil {
		return fmt.Errorf("decrypt rpc: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("decrypt failed: %s", resp.Error)
	}
	fmt.Println("  Decrypt via agent:")
	for k, orig := range original {
		fmt.Printf("    %s %s = %q\n", check(resp.Values[k] == orig), k, resp.Values[k])
	}

	statusResp, err := testRPC(sockPath, agent.Request{Op: "status"})
	if err != nil {
		return fmt.Errorf("status rpc: %w", err)
	}
	fmt.Printf("  Status: ttl_remaining=%s\n", statusResp.TTLRemaining)

	// --- Command runner (Phase 3) ---
	fmt.Println("\n=== Command Runner ===")

	// Create a test command directory.
	testCmdDir := filepath.Join(dir, "commands", "greet")
	if err := os.MkdirAll(testCmdDir, 0700); err != nil {
		return err
	}

	// Write secrets.toml into the command dir.
	if err := os.WriteFile(filepath.Join(testCmdDir, "secrets.toml"), tomlBytes, 0600); err != nil {
		return err
	}

	// Write command.sh template.
	cmdSh := `echo "token={{.token}} client={{.client_id}} arg0={{index .Args 0}} cmd={{.Cmd}}"` + "\n"
	if err := os.WriteFile(filepath.Join(testCmdDir, "command.sh"), []byte(cmdSh), 0600); err != nil {
		return err
	}

	// Exercise the template + execute flow directly (agent is already running).
	tmpl, err := template.New("command.sh").Parse(cmdSh)
	if err != nil {
		return err
	}

	ctx := make(map[string]interface{}, len(resp.Values)+2)
	for k, v := range resp.Values {
		ctx[k] = v
	}
	ctx["Args"] = []string{"hello"}
	ctx["Cmd"] = "greet"

	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, ctx); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	fmt.Printf("  Rendered: %s", rendered.String())

	// Execute and capture output.
	sh := exec.Command("sh", "-c", rendered.String())
	out, err := sh.Output()
	if err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	output := strings.TrimSpace(string(out))
	expected := "token=super-secret-token-123 client=not-secret-plaintext arg0=hello cmd=greet"
	fmt.Printf("  Output:   %s\n", output)
	fmt.Printf("  %s command runner output matches\n", check(output == expected))
	if output != expected {
		return fmt.Errorf("expected %q, got %q", expected, output)
	}

	// --- Shutdown ---
	fmt.Println("\n=== Shutdown ===")
	pidFile := filepath.Join(runtimeDir, "agent.pid")
	pidData, _ := os.ReadFile(pidFile)
	fmt.Printf("  Agent PID: %s\n", strings.TrimSpace(string(pidData)))

	go func() {
		time.Sleep(50 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGINT)
	}()

	select {
	case err := <-agentDone:
		if err != nil {
			return fmt.Errorf("agent exit error: %w", err)
		}
		fmt.Println("  Agent shut down cleanly")
	case <-time.After(3 * time.Second):
		return fmt.Errorf("agent did not shut down within 3s")
	}

	if _, err := os.Stat(sockPath); err == nil {
		return fmt.Errorf("socket file not cleaned up")
	}
	if _, err := os.Stat(pidFile); err == nil {
		return fmt.Errorf("pid file not cleaned up")
	}
	fmt.Println("  Socket and PID files cleaned up")

	fmt.Println("\n✓ All tests passed")
	return nil
}

func testRPC(sockPath string, req agent.Request) (*agent.Response, error) {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp agent.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", path)
}

func check(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}
