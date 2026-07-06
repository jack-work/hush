# Porting hush to Windows

*Rough survey and a plan. Second attempt — branch `windows2`.*

hush today is a small Go daemon + CLI that keeps age-decrypted secrets
in RAM and hands plaintext to whitelisted commands over an **AF_UNIX
socket**, gated by filesystem mode `0600` and a single-instance
**flock(2)** on `agent.pid`. Most of it is portable Go; a handful of
Unixisms need seams before it will build on Windows at all.

---

## The Windows-hostile surface, ranked

| Where | What's Unixy | Windows story |
|---|---|---|
| `net.Listen("unix", …)` in `agent/agent.go`, `client/client.go`, `agent/spawn.go`, `cmd/test.go` | AF_UNIX socket + `chmod 0600` | Windows 10+ *does* support AF_UNIX and Go's `net` handles it, but there is no `chmod 0600` gate. Real ACLs are required. Cleaner option: switch to **named pipes** (`\\.\pipe\hush-<sid>`), which have native SDDL for per-user access. |
| `syscall.Flock` in `agent/agent.go`, `cmd/down.go`, `cmd/test.go` | POSIX advisory lock | No flock on Windows. Use `LockFileEx` from `golang.org/x/sys/windows`, or `os.OpenFile` with exclusive-share semantics. Hide behind an `internal/singleton` interface, split `_unix.go` / `_windows.go`. |
| `signal.Notify(SIGINT, SIGTERM)` in `agent/agent.go`; `proc.Signal(SIGTERM)` in `cmd/down.go` | Unix signals | Windows can't `SIGTERM` a foreign process. Best fix: add an `Op: "shutdown"` RPC to the protocol and have `hush down` call it. Works everywhere; the flock-poll shutdown wait already generalizes. |
| Daemonization in `cmd/up.go` / `agent/spawn.go` (`exec.Cmd.ExtraFiles` fd 3, orphan-on-parent-exit) | inherits fd 3 across `fork+exec` | `ExtraFiles` is a Unix-only field. On Windows: `SysProcAttr{HideWindow: true, CreationFlags: DETACHED_PROCESS \| CREATE_NEW_PROCESS_GROUP}` for detach, and pass the identity via an anonymous pipe whose handle is duplicated inheritable into the child (via `ProcThreadAttributeList`). Simpler v1: pass identity on the child's `stdin` and close it. |
| Socket permissions `0600` | file-mode gating | Meaningless on Windows AF_UNIX. On a named pipe: set an SDDL granting access only to the current user's SID. Must fail closed if the security descriptor can't be applied — this *is* the security posture. |
| XDG dir resolution in `config/config.go` | `~/.config`, `$XDG_RUNTIME_DIR`, `os.TempDir()` | Add `%APPDATA%\hush` (config), `%LOCALAPPDATA%\hush\state` (state), `%LOCALAPPDATA%\hush\run` (runtime). No `XDG_RUNTIME_DIR` analogue exists; a per-user LOCALAPPDATA subdir with a user-only DACL is the equivalent. Keep the `HUSH_*_DIR` overrides. |
| `os.Pipe()` daemon key handoff (`cmd/up.go`, `agent/spawn.go`) | pipe survives `fork+exec` | Windows pipes work but the write/read handle must be marked inheritable and passed through startup info. Handled once inside `internal/daemon`. |
| `term.ReadPassword(int(os.Stdin.Fd()))` (many files) | Unix-fd int | `golang.org/x/term` already handles Windows. No change. |
| `openBrowser` in `cmd/oauth_login.go` | branches on `runtime.GOOS` | Windows branch already present (`rundll32 url.dll,FileProtocolHandler`). Good. |
| `unlock/keyring` via `zalando/go-keyring` | libsecret / Keychain | Already falls through to `wincred` (indirect dep). Free lunch. |
| `unlock/exec` — user-supplied argv (`pass`, `op`, `rbw`) | `exec.Command` | Works on Windows; user's job to install `op.exe` etc. |

---

## The port shape

### 1. Extract three seams, split per-platform via build tags

- **`internal/singleton`** — `Acquire() / Release()`
  - `singleton_unix.go`: current `syscall.Flock` on `agent.pid`.
  - `singleton_windows.go`: `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY)`.

- **`internal/ipc`** — `Listen(name) (net.Listener, error)`, `Dial(name) (net.Conn, error)`
  - `ipc_unix.go`: `net.Listen("unix", sockPath)` + `os.Chmod(0600)`.
  - `ipc_windows.go`: named pipe via `github.com/Microsoft/go-winio` with an SDDL scoped to the current user's SID.
  - `client/`, `agent/`, `cmd/test.go` all stop caring which is in use.

- **`internal/daemon`** — `Spawn(exe, args []string, identity []byte) (pid int, err error)` and `RunChild() ([]byte, error)`
  - `daemon_unix.go`: current pipe + `ExtraFiles` fd 3 dance.
  - `daemon_windows.go`: `DETACHED_PROCESS` + inheritable pipe handle via `ProcThreadAttributeList`, or stdin-passthrough as a v1 shortcut.

### 2. Replace `SIGTERM` with an RPC

Add `Op: "shutdown"` to `agent/protocol.go`. Handler closes the listener and returns. `hush down` calls it via the client and polls the singleton lock for release (existing logic). Unix keeps signal-based shutdown as a fallback for `kill` from outside.

### 3. Enforce access control at listen time

On Windows: name the pipe `\\.\pipe\hush-<user-sid>` and construct an SDDL like `D:P(A;;GA;;;<sid>)`. `go-winio` accepts a `PipeConfig.SecurityDescriptor`. Refuse to start if the SD cannot be applied.

### 4. Directory resolution

Add `dirs_windows.go`:
- Config: `%APPDATA%\hush`
- State:  `%LOCALAPPDATA%\hush\state`
- Runtime: `%LOCALAPPDATA%\hush\run`

Apply an explicit user-only DACL when creating `RuntimeDir` and `StateDir` (encrypted OAuth blobs live there). The `HUSH_CONFIG_DIR` / `HUSH_STATE_DIR` / `HUSH_RUNTIME_DIR` overrides continue to win.

### 5. Build hygiene

- Add a CI job: `GOOS=windows GOARCH=amd64 go build ./...`. Right now this fails on the top-level `syscall.Flock` and `syscall.SIGTERM` references — a green cross-compile is the definition-of-done gate.
- Keep `flake.nix` for the Linux dev shell unchanged.

### 6. What already works — do not touch

- Age crypto (`filippo.io/age`), passphrase prompt (`golang.org/x/term`), keyring lookup (`zalando/go-keyring` → wincred), OAuth flow, browser open, exec-based unlock.

---

## Known limitation carried over

Go copies the passphrase into an immutable string internally; that copy
can't be zeroed on any OS. README already documents this — Windows
neither helps nor hurts.

---

## Definition of done for `windows2`

1. `GOOS=windows go build ./...` succeeds with no build tags stripped.
2. `hush up`, `hush down`, `hush status`, `hush encrypt-value`, `hush brave "…"` all work end-to-end on a Windows 10+ box.
3. Named-pipe SD is scoped to the current user's SID; a second local user cannot open the pipe. Verified with `sc.exe`-style probing or a second-user test.
4. `hush down` uses the RPC path on both OSes; Unix keeps signal fallback.
5. No regression on Linux/macOS end-to-end tests in `e2e/`.

---

*One clean seam per concern, one build-tag split per seam, one RPC to
retire the signal. Everything else already ports for free.*
