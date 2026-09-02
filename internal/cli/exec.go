package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"
)

// buildChild turns a command spec plus its decrypted secrets into the
// process that will run, in one of two shapes.
//
// Scriptless (spec.Exec set): the binary is executed directly. No shell, no
// template, no interpreter — caller arguments are argv elements and cannot
// become program text. This is the preferred shape.
//
// Script: the command script is rendered as a template and handed to sh.
// Under DeliveryEnv the secrets are withheld from the template context, so
// a script that still references {{.token}} fails loudly instead of
// silently rendering an empty credential.
//
// The returned cleanup must always be called, even on error.
func buildChild(spec *Spec, name, scriptName, script string, values map[string]string, extra []string) (*exec.Cmd, func(), error) {
	noop := func() {}

	secretEnv, err := spec.SecretEnv(values)
	if err != nil {
		return nil, noop, err
	}

	if spec.Scriptless() {
		argv := append(append([]string{}, spec.Args...), extra...)
		cmd := exec.Command(spec.Exec, argv...)
		cmd.Env = childEnv(secretEnv)
		return cmd, noop, nil
	}

	rendered, err := renderScript(spec, name, scriptName, script, values, extra)
	if err != nil {
		return nil, noop, err
	}

	cmd, cleanup, err := shellCommand(rendered, scriptName, "hush-"+name, extra)
	if err != nil {
		return nil, cleanup, err
	}
	if spec.EnvDelivery() {
		cmd.Env = childEnv(secretEnv)
	} else {
		cmd.Env = childEnv(nil)
	}
	return cmd, cleanup, nil
}

// renderScript executes the command script as a text/template.
//
// The context differs by delivery. Under "script" it carries the secrets
// (legacy behavior). Under "env" it does not, and missingkey=error turns a
// leftover {{.token}} into a clear message naming the migration rather than
// an empty string that produces a mystifying 401 an hour later.
func renderScript(spec *Spec, name, scriptName, script string, values map[string]string, extra []string) (string, error) {
	ctx := make(map[string]any, len(values)+2)
	if !spec.EnvDelivery() {
		for k, v := range values {
			ctx[k] = v
		}
	}
	ctx["Args"] = extra
	ctx["Cmd"] = name

	tmpl := template.New(scriptName)
	if spec.EnvDelivery() {
		tmpl = tmpl.Option("missingkey=error")
	}
	tmpl, err := tmpl.Parse(script)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, ctx); err != nil {
		if spec.EnvDelivery() {
			return "", fmt.Errorf("render template: %w\n\n"+
				"this command declares delivery = %q, so secrets are not available to the\n"+
				"template. read them from the environment instead: \"$%s\".",
				err, DeliveryEnv, anyEnvName(spec))
		}
		return "", fmt.Errorf("render template: %w", err)
	}
	return out.String(), nil
}

func anyEnvName(spec *Spec) string {
	for _, v := range spec.Secrets {
		return v
	}
	return "YOUR_VAR"
}

// childEnv builds the environment handed to a brokered process: the
// inherited environment with the shims directory removed from PATH, plus
// the command's declared secrets.
//
// Stripping the shims directory is what stops a command from re-entering
// hush. A shim named `curl` early on PATH would otherwise catch the `curl`
// that the brokered command itself invokes, and hush would call itself
// until the process table gave out.
func childEnv(secretEnv []string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+len(secretEnv))
	for _, kv := range base {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "PATH" {
			out = append(out, "PATH="+stripShimDir(v))
			continue
		}
		out = append(out, kv)
	}
	return append(out, secretEnv...)
}

// stripShimDir removes the hush shims directory from a PATH value.
func stripShimDir(path string) string {
	dir := shimDir()
	if dir == "" {
		return path
	}
	parts := strings.Split(path, string(os.PathListSeparator))
	kept := parts[:0]
	for _, p := range parts {
		if p == dir {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, string(os.PathListSeparator))
}

// runBrokered runs the process, killing it if it outlives the timeout. A zero
// timeout waits forever, which is the historical behavior.
func runBrokered(cmd *exec.Cmd, timeout time.Duration) error {
	if timeout <= 0 {
		return cmd.Run()
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("timed out after %s", timeout)
	}
}
