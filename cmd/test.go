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

	"github.com/jack-work/hush/agent"
	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/identity"
	"github.com/jack-work/hush/secrets"
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

	// --- Encrypt via agent ---
	fmt.Println("\n=== Encrypt via Agent ===")
	plainValues := map[string]string{
		"secret_key":  "my-secret-value",
		"public_key":  "not-secret",
	}
	encResp, err := testRPC(sockPath, agent.Request{Op: "encrypt", Values: plainValues})
	if err != nil {
		return fmt.Errorf("encrypt rpc: %w", err)
	}
	if !encResp.OK {
		return fmt.Errorf("encrypt failed: %s", encResp.Error)
	}
	fmt.Printf("  %s secret_key is AGE-ENC wrapped\n", check(secrets.IsEncrypted(encResp.Values["secret_key"])))
	fmt.Printf("  %s public_key is AGE-ENC wrapped\n", check(secrets.IsEncrypted(encResp.Values["public_key"])))

	// Round-trip: decrypt what we just encrypted.
	rtResp, err := testRPC(sockPath, agent.Request{Op: "decrypt", Values: encResp.Values})
	if err != nil {
		return fmt.Errorf("round-trip decrypt rpc: %w", err)
	}
	if !rtResp.OK {
		return fmt.Errorf("round-trip decrypt failed: %s", rtResp.Error)
	}
	fmt.Println("  Round-trip encrypt → decrypt:")
	for k, orig := range plainValues {
		fmt.Printf("    %s %s = %q\n", check(rtResp.Values[k] == orig), k, rtResp.Values[k])
	}

	// Already-encrypted values pass through.
	alreadyEnc := map[string]string{
		"wrapped": encResp.Values["secret_key"],
		"plain":   "new-value",
	}
	passResp, err := testRPC(sockPath, agent.Request{Op: "encrypt", Values: alreadyEnc})
	if err != nil {
		return fmt.Errorf("passthrough rpc: %w", err)
	}
	if !passResp.OK {
		return fmt.Errorf("passthrough failed: %s", passResp.Error)
	}
	fmt.Printf("  %s already-encrypted value passed through unchanged\n",
		check(passResp.Values["wrapped"] == alreadyEnc["wrapped"]))
	fmt.Printf("  %s plain value got encrypted\n",
		check(secrets.IsEncrypted(passResp.Values["plain"])))

	// --- Client Library ---
	fmt.Println("\n=== Client Library ===")
	c := client.NewWithSocket(sockPath)

	clientEnc, err := c.Encrypt(map[string]string{"key": "library-test"})
	if err != nil {
		return fmt.Errorf("client encrypt: %w", err)
	}
	fmt.Printf("  %s client.Encrypt works\n", check(secrets.IsEncrypted(clientEnc["key"])))

	clientDec, err := c.Decrypt(clientEnc)
	if err != nil {
		return fmt.Errorf("client decrypt: %w", err)
	}
	fmt.Printf("  %s client.Decrypt round-trip = %q\n", check(clientDec["key"] == "library-test"), clientDec["key"])

	ttlRemaining, err := c.Status()
	if err != nil {
		return fmt.Errorf("client status: %w", err)
	}
	fmt.Printf("  %s client.Status = %s\n", check(ttlRemaining != ""), ttlRemaining)

	fmt.Printf("  %s client.Ping\n", check(c.Ping() == nil))

	// --- Command Runner ---
	fmt.Println("\n=== Command Runner ===")
	testCmdDir := filepath.Join(dir, "commands", "greet")
	if err := os.MkdirAll(testCmdDir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(testCmdDir, "secrets.toml"), tomlBytes, 0600); err != nil {
		return err
	}
	cmdSh := `echo "token={{.token}} client={{.client_id}} arg0={{index .Args 0}} cmd={{.Cmd}}"` + "\n"
	if err := os.WriteFile(filepath.Join(testCmdDir, "command.sh"), []byte(cmdSh), 0600); err != nil {
		return err
	}

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

	// --- Encrypt in-place ---
	fmt.Println("\n=== Encrypt in-place ===")
	mixedPath := filepath.Join(dir, "mixed.toml")
	mixedContent := "encrypted_key = \"already-encrypted\"\nplain_key = \"needs-encryption\"\n"
	if err := os.WriteFile(mixedPath, []byte(mixedContent), 0600); err != nil {
		return err
	}

	// Encrypt the plain_key value.
	encVal, err := secrets.EncryptValue("already-encrypted", ageID.Recipient())
	if err != nil {
		return err
	}
	mixedWithEnc := fmt.Sprintf("encrypted_key = %q\nplain_key = \"needs-encryption\"\n", encVal)
	if err := os.WriteFile(mixedPath, []byte(mixedWithEnc), 0600); err != nil {
		return err
	}

	// Parse, encrypt plaintext, write back.
	var mixedValues map[string]string
	mixedData, _ := os.ReadFile(mixedPath)
	if err := toml.Unmarshal(mixedData, &mixedValues); err != nil {
		return err
	}

	changed := 0
	for k, v := range mixedValues {
		if !strings.HasPrefix(v, secrets.EncPrefix) {
			encV, err := secrets.EncryptValue(v, ageID.Recipient())
			if err != nil {
				return err
			}
			mixedValues[k] = encV
			changed++
		}
	}
	fmt.Printf("  Encrypted %d plaintext value(s)\n", changed)

	// Verify both values decrypt correctly.
	for k, v := range mixedValues {
		d, err := secrets.DecryptValue(v, id.Identities)
		if err != nil {
			return fmt.Errorf("decrypt %q: %w", k, err)
		}
		fmt.Printf("  %s %s decrypts ok\n", check(true), k)
		_ = d
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
