# Windows port: implementation plan

*Companion to `docs/windows-port.md`. That doc is the survey; this is the
actionable plan, corrected against what `GOOS=windows go build ./...`
actually reports and what the prior local `windows` branch learned the
hard way.*

---

## Ground truth (measured, not guessed)

Ran `GOOS=windows GOARCH=amd64 go build ./...` and a per-package build on
`origin/windows2`.

**The only hard compile blocker** is the single-instance lock:

```
agent/agent.go:  syscall.Flock, syscall.LOCK_EX, syscall.LOCK_NB   (undefined on windows)
cmd/down.go:     syscall.Flock, syscall.LOCK_SH, syscall.LOCK_UN
cmd/test.go:     syscall.Flock, syscall.LOCK_SH, syscall.LOCK_UN
e2e/e2e_test.go: syscall.Flock, syscall.LOCK_SH, syscall.LOCK_UN
```

**These packages already build AND run clean on Windows today:**
`config`, `unlock`, `oauth`, `identity`, `secrets`.

That last point is the important one. The keyring path
(`zalando/go-keyring` v0.2.8, which pulls `danieljoos/wincred` as an
indirect dep for the Windows Credential Manager backend) compiles and
links on Windows with no code changes. `unlock/keyring.go`,
`unlock/auto.go`, and `cmd/keyring.go` are portable as written.

So keyring integration is a free lunch at the code layer. The real job
is making the agent reachable at all so the unlock path runs. Nothing to
"add" for keychain; everything to fix around it.

**Runtime failures that compile but break on Windows:**

| Symptom | Where | Cause |
|---|---|---|
| daemon spawn dies at `Start` | `cmd/up.go`, `cmd/run.go`, `agent/spawn.go` | `child.ExtraFiles` -> `exec.Start` returns "not supported by windows" (verified). fd-3 identity handoff is Unix-only. |
| `hush down` cannot stop the agent | `cmd/down.go` | `proc.Signal(syscall.SIGTERM)` fails; only `Kill` works on Windows. |
| agent ignores shutdown signal | `agent/agent.go` | `signal.Notify(SIGTERM)` never fires on Windows. |
| `hush run` cannot execute a command | `cmd/run.go`, `cmd/test.go` | `exec.Command("sh", "-c", ...)`, no `sh` on Windows. |

**Not covered by the survey, but load-bearing:** Windows terminals
(Windows Terminal, VS Code, `conhost`) launch child processes inside a
job object with `KILL_ON_JOB_CLOSE`. A naively detached daemon dies when
the launching shell closes. `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`
does NOT escape this; `CREATE_BREAKAWAY_FROM_JOB` is silently ignored
when the job forbids breakaway. The prior local `windows` branch solved
it with a WMI `Win32_Process.Create` spawn (the WMI host creates the
process outside the caller's job). Fold that in.

---

## Branch strategy

- Base the work on **`origin/windows2`**. It carries the unlock package
  (auto/keyring/exec/passphrase), oauth, the managed embed path, config
  dir overrides, and the e2e harness.
- Do **not** continue the local `windows` branch. Its merge-base with
  `windows2` is `a7aa641` (an old master); it predates the entire unlock
  package. It is a source of solved mechanics, not a base.
- Mine the old `windows` branch's `platform/` package for the parts it
  got right (WMI spawn, launcher `.cmd`, shell selection, dir resolution,
  process liveness via `OpenProcess`), but re-shape them onto the seams
  the survey prescribes rather than one flat `platform` package.
- Suggested start: `git switch -c feat/windows origin/windows2`.

---

## The seams

One concern per seam, one build-tag split per seam. Order is by
dependency: seam 1 unblocks the compile; the rest make it work.

### 1. `internal/singleton` (unblocks the build)

`Acquire(pidPath) (release func, err error)` and a `Probe(pidPath) bool`
(is the lock free?) used by `down`.

- `singleton_unix.go`: today's `syscall.Flock(LOCK_EX|LOCK_NB)` on
  `agent.pid`, with `LOCK_SH` probe for `down`.
- `singleton_windows.go`: `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK |
  LOCKFILE_FAIL_IMMEDIATELY)` from `golang.org/x/sys/windows` (already an
  indirect dep, no go.mod change). `UnlockFileEx` on release.

Callers to route through it: `agent.acquireLock`, `cmd/down.lockFree`,
`cmd/test.go`, `e2e/e2e_test.go`. Keep the invariant the code documents:
the pid file is the lock inode and is never unlinked.

### 2. `internal/ipc` (transport)

`Listen(name) (net.Listener, error)`, `Dial(name) (net.Conn, error)`.

**v1 recommendation: keep AF_UNIX on both OSes.** Windows 10+ supports
it, `net` handles it, the old branch shipped it, and it adds zero
dependencies. The socket lives in a per-user runtime dir (see seam 5)
whose DACL already scopes to the current user; drop the `chmod 0600` on
Windows (meaningless on AF_UNIX there).

- `ipc_unix.go`: `net.Listen("unix", path)` + `os.Chmod(0600)`.
- `ipc_windows.go`: `net.Listen("unix", path)`, no chmod.

Callers: `agent/agent.go` (listen), `client/client.go`,
`agent/spawn.go`, `cmd/test.go` (dial).

**Follow-up hardening (separate change):** named pipe via
`github.com/Microsoft/go-winio` with an SDDL scoped to the user's SID
(`D:P(A;;GA;;;<sid>)`), refusing to start if the SD cannot be applied.
This is the survey's stated target and its DoD item 3. Trade-off to make
explicit: an AF_UNIX socket file carries no per-connection security
descriptor, so on Windows the directory DACL is the only gate. For a
single-user dev box that is acceptable; the pipe is the right answer for
a shared machine. Ship AF_UNIX first to unblock figaro, harden after.

### 3. Shutdown RPC (retire `SIGTERM`)

Add `Op: "shutdown"` to `agent/protocol.go`. Handler closes the listener
and returns. `cmd/down` calls `client.Shutdown()` then polls the
singleton for release (the existing wait loop generalizes). Keep the
Unix `signal.Notify(SIGINT, SIGTERM)` handler behind a build tag as a
fallback for an external `kill`; Windows has no equivalent and does not
need one.

This is wire-protocol surface. A new op is purely additive (old clients
never send it, old agents reject an unknown op cleanly), so it is safe,
but call it out in the change summary per repo disclosure rules.

### 4. `internal/daemon` (the subtle one)

`Spawn(exe string, args []string, id *identity.DecryptedIdentity) (pid int, err error)`
and `RunChild() (*identity.DecryptedIdentity, error)`.

Two constraints are in tension on Windows:

- **(a) Escape the job object** so the daemon survives the shell closing.
  Requires the WMI `Win32_Process.Create` spawn (or a breakaway the job
  permits). A WMI-spawned child runs under the WMI host, not us.
- **(b) Hand the decrypted identity to the child without it touching
  disk.** This is hush's entire premise, and figaro invariant #10
  ("secrets never hit disk in plaintext").

The tension: a WMI-spawned child does **not** inherit our pipe or stdin
handles, so the Unix fd-3 trick (and the survey's "stdin passthrough"
shortcut) cannot reach it.

**Resolution: a short-lived, per-user named pipe for the handoff.**

1. Parent creates `\\.\pipe\hush-handoff-<rand>` with a user-only SD.
2. Parent writes a launcher `.cmd` that sets `HUSH_AGENT_CHILD=1`,
   `HUSH_IDENTITY_PIPE=<name>`, and redirects stderr to `state\hush.log`.
3. Parent WMI-spawns the launcher.
4. Child connects to the pipe, reads the identity, parent writes then
   closes. In-memory, survives the WMI boundary, open for milliseconds.

The prior branch used `HUSH_IDENTITY_FILE` (a real temp file). It works,
but writes the age identity to disk for a beat: a posture regression we
should not ship as the default. Keep the temp-file path only as an
opt-in, documented fallback if the named pipe proves flaky in the field.

Keep the launcher's stderr redirect to `state\hush.log`; it is cheap
crash forensics and the old branch already relied on it.

- `daemon_unix.go`: unchanged. `os.Pipe` + `ExtraFiles` fd 3.
- `daemon_windows.go`: WMI spawn + launcher `.cmd` + named-pipe handoff,
  fallback to `CreateProcess | BREAKAWAY_FROM_JOB` (+ temp-file handoff)
  when WMI is unavailable.

Fix `cmd/up.go`, `cmd/run.go`, and `agent/spawn.go` to route through this
seam. Also read the real agent PID back from `agent.pid` after spawn (the
WMI/launcher PID is the wrapper, not the agent) for the "agent started"
message; the old branch already did this.

### 5. Dirs, shell, editor

Port from the old branch's `platform` package, split per OS.

- **Dirs** (`dirs_windows.go`): Config `%APPDATA%\hush`, State
  `%LOCALAPPDATA%\hush\state`, Runtime `%LOCALAPPDATA%\hush\run`. Apply an
  explicit user-only DACL when creating Runtime and State (encrypted
  OAuth blobs live there). `HUSH_CONFIG_DIR` / `HUSH_STATE_DIR` /
  `HUSH_RUNTIME_DIR` continue to win (already handled in
  `config/config.go`). Note: the old branch put runtime under `TempDir`;
  `%LOCALAPPDATA%\hush\run` is better (persists, user-scoped) and matches
  the survey.
- **`hush run` shell** (`cmd/run.go`, `cmd/test.go`): replace the bare
  `exec.Command("sh", "-c", ...)` with a shell seam. `sh -c` on Unix; on
  Windows pick `pwsh` vs `cmd` by the command-script extension
  (`.ps1` / `.cmd`), writing multiline scripts to a temp file (neither
  `cmd /C` nor `pwsh -Command` handle multiline reliably). This changes
  the per-OS default command template (`command.sh` on Unix vs
  `command.ps1` on Windows); additive, per-OS, no migration.
- **Editor** (`cmd/edit.go`): the `vi` default is fine (`vi` exists in
  Git Bash). Optional: make it a small seam later. Low priority.
- **Browser** (`cmd/oauth_login.go`): already branches on `runtime.GOOS`
  with a working Windows arm. Leave it.

### 6. Build hygiene

- CI job: `GOOS=windows GOARCH=amd64 go build ./...` green is the
  definition-of-done gate. It fails today only on seam 1.
- Test files that touch `syscall.Flock` directly (`cmd/test.go`,
  `e2e/e2e_test.go`) either route through `internal/singleton` or split
  into `_unix.go` / `_windows.go` (the old branch added
  `cmd/test_unix.go` / `cmd/test_windows.go`; follow that shape).
- Keep `flake.nix` and the Linux dev shell untouched.

---

## Decisions to confirm before coding

1. **IPC transport.** AF_UNIX v1 (fast, zero deps, proven) vs named pipes
   now (survey's target, real SDDL, adds `go-winio`). Recommendation:
   AF_UNIX for v1 to unblock figaro, named pipe as a fast-follow. Flag if
   the target machine is multi-user (then do the pipe first).
2. **Identity handoff on Windows.** Named-pipe (in-memory, recommended)
   vs temp-file (simpler, brief disk exposure). Recommendation:
   named-pipe; temp-file only as an opt-in fallback.
3. **Package placement.** `internal/singleton`, `internal/ipc`,
   `internal/daemon` per the survey, vs folding into existing packages.
   Recommendation: follow the survey; it matches Go norms and keeps the
   call sites transport-agnostic.

---

## Definition of done

1. `GOOS=windows go build ./...` green, no build tags stripped.
2. `up`, `down`, `status`, `encrypt-value`, `run` work end-to-end on a
   Windows 10+ box.
3. The daemon survives closing the launching terminal (job-object escape
   verified: close the shell, `hush status` from a new shell still
   answers).
4. The decrypted identity is never written to disk in plaintext during
   handoff.
5. Unlock `auto` + `keyring` path works: first `hush up` prompts once and
   stores to Credential Manager; subsequent `hush up` is silent.
   `hush keyring set` / `get` / `clear` operate on Credential Manager.
6. `hush down` uses the RPC path on both OSes; Unix keeps the signal
   fallback.
7. No regression on the Linux/macOS `e2e/` tests.

---

## After hush: figaro

hush is the gating dependency and the cleaner isolated task, which is why
it goes first. Once hush ships a working Windows binary and the `managed`
unlock path runs, figaro's dependency turns green. figaro's own Windows
port (socket dial in the client, daemon fork and signal handling in
`cmd/figaro/main.go`, the `q` / `l` symlinks that the nix `postInstall`
provides) is a separate pass. Track it separately; this plan stops at
hush.
