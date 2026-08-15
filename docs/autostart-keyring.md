# Autostart + keyring: silent hush on Windows and Linux

Goal: never type a passphrase again. Any program that asks hush for a
secret (figaro, `hush <command>`, your own app using the client library)
starts the agent on demand, unlocks it from the OS keyring, and answers.
No `hush up -d`, no prompt.

Two pieces make this work:

1. **Autostart** (built in): when a secret is requested and no agent is
   running, hush spawns one. On Windows it spawns through WMI so the
   daemon survives the terminal that launched it; on Linux it detaches
   the usual way.
2. **Keyring unlock** (`unlock.method = auto`, the default): the agent
   reads the identity passphrase from the OS keyring (Windows Credential
   Manager / macOS Keychain / libsecret) instead of prompting. When the
   keyring holds the passphrase, unlock is silent.

---

## Windows

### 1. Build / install

```powershell
cd C:\Users\<you>\dev\hush
go build -o hush.exe .
# put hush.exe on your PATH, or call it by full path
```

Config lives in `%APPDATA%\hush` (i.e.
`C:\Users\<you>\AppData\Roaming\hush`). State (logs, OAuth blobs) lives in
`%LOCALAPPDATA%\hush`. The runtime socket lives under `%TEMP%\hush`.

### 2. Have an identity

If `%APPDATA%\hush\identity.age` already exists (earlier hush builds put
it there), keep it: your existing secrets are encrypted to its key.

Otherwise create one:

```powershell
hush init          # prompts for a passphrase, writes identity.age + .pub
```

### 3. Seed the keyring

This is the step that makes startup silent. Store the identity's
passphrase in Windows Credential Manager under service `hush`, account
`default`:

```powershell
hush keyring set   # prompts twice, confirms they match
```

Enter the **same passphrase** that unlocks `identity.age`. (If you have an
existing identity, that is the passphrase you chose when it was created.)

Check it landed (never prints the value):

```powershell
hush keyring get   # -> service="hush" account="default": present (N bytes)
```

> Alternative: skip `hush keyring set` and just run `hush up` once. With
> `method = auto` and an empty keyring, hush prompts a single time and
> saves what you type. Every start after that is silent.

### 4. Confirm silent startup

```powershell
hush up -d         # should print "agent started ...", NO passphrase prompt
hush status        # Agent: running
hush down          # stops it over the socket
```

### 5. That's it: autostart is now invisible

You never need `hush up -d` again. The next secret request brings the
agent up silently:

```powershell
hush somecommand           # runs commands\somecommand\command.ps1 with secrets injected
"AGE-ENC[...]" | hush secret decrypt -  # autostarts, decrypts, prints
```

figaro (which embeds hush through the managed library) gets the same
behavior for free.

### Recovery: wrong saved passphrase

If you seeded the keyring with the wrong passphrase, startup will fail
silently every time. Clear it and redo step 3:

```powershell
hush keyring clear
hush keyring set
```

---

## Linux

Identical flow, with two differences:

- Config is `~/.config/hush`, state `~/.local/state/hush`.
- The keyring backend is the **Secret Service** (gnome-keyring or
  KWallet), which needs a running desktop session (or
  `gnome-keyring-daemon --start`). On a headless box there is no Secret
  Service; use the `exec` backend instead (below).

```bash
go build -o hush .
hush init            # if you don't have an identity yet
hush keyring set     # stores under libsecret
hush up -d           # silent
```

### Headless Linux (no Secret Service)

Point hush at a password manager you already have (`pass`, `rbw`, `op`,
...). In `~/.config/hush/hush.toml`:

```toml
[unlock]
method = "exec"
exec = ["pass", "show", "hush/passphrase"]
```

hush runs that command and reads the passphrase from its stdout. Autostart
stays silent.

---

## The config (optional; defaults already do the right thing)

`hush.toml` in the config dir. You only need this to change defaults:

```toml
[unlock]
method = "auto"        # auto (default) | keyring | exec | passphrase

[unlock.keyring]
service = "hush"       # Credential Manager / Keychain / libsecret entry
account = "default"
```

- `auto` (default): try the keyring; if empty, prompt once and save it.
- `keyring`: keyring only, error if missing (no prompt).
- `exec`: run `unlock.exec` and read the passphrase from stdout.
- `passphrase`: always prompt on the terminal (the old behavior).

`HUSH_KEYRING_SERVICE` overrides the service name for a single run, handy
for keeping separate entries per project.

---

## Security notes

- The passphrase in the keyring is protected by your OS login session
  (DPAPI on Windows, your login keyring on Linux). It is only as strong
  as your desktop login.
- The decrypted identity is handed to the spawned agent over an in-memory
  channel (a pipe on Linux, a short-lived local socket on Windows); it is
  never written to disk in plaintext.
- On Windows the agent socket lives in your per-user temp directory. This
  is a single-user posture: it relies on that directory's user-only ACL,
  not on a per-connection security descriptor. A named-pipe transport with
  an explicit per-SID descriptor is the hardening path if you ever share
  the machine.
