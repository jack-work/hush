package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/gluck/hush/agent"
	"github.com/gluck/hush/identity"
)

func runCmd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	name := args[0]
	extra := args[1:]

	cmdDir := filepath.Join(cfg.CommandsDir, name)
	if _, err := os.Stat(cmdDir); err != nil {
		return fmt.Errorf("command %q not found (looked in %s)", name, cmdDir)
	}

	// Read command.sh.
	cmdFile := filepath.Join(cmdDir, "command.sh")
	cmdBytes, err := os.ReadFile(cmdFile)
	if err != nil {
		return fmt.Errorf("command %q missing command.sh (expected at %s)", name, cmdFile)
	}

	// Decrypt secrets if secrets.toml exists.
	values := make(map[string]string)
	secretsFile := filepath.Join(cmdDir, "secrets.toml")
	if _, err := os.Stat(secretsFile); err == nil {
		var decErr error
		values, decErr = decryptViaAgent(secretsFile)
		if decErr != nil {
			return decErr
		}
	}

	// Build template context: secrets at top level + Args + Cmd.
	ctx := make(map[string]interface{}, len(values)+2)
	for k, v := range values {
		ctx[k] = v
	}
	ctx["Args"] = extra
	ctx["Cmd"] = name

	// Render template.
	tmpl, err := template.New("command.sh").Parse(string(cmdBytes))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, ctx); err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	// Execute via sh -c.
	sh := exec.Command("sh", "-c", rendered.String())
	sh.Stdin = os.Stdin
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr

	if err := sh.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

// decryptViaAgent reads the secrets TOML file and sends it to the agent for
// decryption. If no agent is running, it starts one implicitly.
func decryptViaAgent(secretsFile string) (map[string]string, error) {
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		return nil, fmt.Errorf("read secrets: %w", err)
	}

	var rawValues map[string]string
	if err := toml.Unmarshal(data, &rawValues); err != nil {
		return nil, fmt.Errorf("parse secrets toml: %w", err)
	}

	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")

	// Ensure agent is running.
	if err := ensureAgent(sockPath); err != nil {
		return nil, err
	}

	// Send decrypt request.
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to agent: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := agent.Request{Op: "decrypt", Values: rawValues}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp agent.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("agent error: %s", resp.Error)
	}
	return resp.Values, nil
}

// ensureAgent checks if an agent is running. If not, starts one implicitly
// (same as hush up -d).
func ensureAgent(sockPath string) error {
	if err := pingAgent(sockPath); err == nil {
		return nil // agent is alive
	}

	// No agent — clean up stale socket if present.
	os.Remove(sockPath)

	fmt.Fprintln(os.Stderr, "No running agent. Starting one...")

	id, err := promptAndUnlock(cfg.IdentityFile)
	if err != nil {
		return err
	}

	ttl := cfg.TTL
	if err := spawnDaemonWithID(id, ttl); err != nil {
		return err
	}

	return nil
}

// spawnDaemonWithID is the same as spawnDaemon but takes an explicit TTL
// and doesn't rely on flag state.
func spawnDaemonWithID(id *identity.DecryptedIdentity, ttl time.Duration) error {
	defer id.Zero()

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	child := exec.Command(exe, "up", "--ttl", ttl.String())
	child.Env = append(os.Environ(), agentChildEnv+"=1")
	child.ExtraFiles = []*os.File{pr}
	child.Stdin = nil
	child.Stdout = nil
	child.Stderr = nil

	if err := child.Start(); err != nil {
		pw.Close()
		pr.Close()
		return fmt.Errorf("start daemon: %w", err)
	}

	pr.Close()
	if _, err := id.WriteTo(pw); err != nil {
		pw.Close()
		return fmt.Errorf("write identity to pipe: %w", err)
	}
	pw.Close()

	if err := waitForAgent(cfg.RuntimeDir, 3*time.Second); err != nil {
		return fmt.Errorf("agent started but not responding: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Agent started (pid %d, ttl %s)\n", child.Process.Pid, ttl)
	return nil
}
