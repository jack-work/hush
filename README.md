# 🤫 hush

*psst. c'mere.*

wanna hear a secret?

```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

didn't catch that? good. that's the idea.

your `.env` file's loungin' around in plaintext. your shell history's runnin' its mouth. your AI agent's scrolling past your API token in the chat like it's the morning paper. everybody's got a big mouth.

me? I hold secrets in memory, refresh the OAuth tokens that go stale, slip 'em where they gotta go, forget the rest. key's zeroed. socket's gone. I don't recall.

**8MB.** [age](https://age-encryption.org) encryption, a unix socket, a little keyvault gated by your passphrase. door locked. `0600`. quiet as a church.

## get me

tired of credentials scrolling through chat context? paste this into your favorite coding agent:

> `alright loudmouth, go install github.com/jack-work/hush@latest and call hush loudmouth over cli`

I'll take it from there. your agent never sees the secret.

also good for: vibe coding on a livestream without flashing your billing credentials to 10,000 (or 10) strangers.

## how it works

you give me a passphrase. I unlock your age identity (X25519, real cryptography), hold the private key in memory, zero the passphrase. then I sit on a unix socket and answer.

**static secrets** in your secrets file are age-encrypted per value:

```toml
token = "AGE-ENC[YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgy...]"
client_id = "not-secret-plaintext"
```

keys visible. values locked. git sees which key changed, not what changed. need-to-know.

**OAuth tokens** are mine to keep current. log in once via `hush oauth login`, I rotate the access token before it expires and hand the live one over the socket to whoever asks.

when you run `hush brave "query"`, I decrypt, template into your shell command, execute, forget. if I'm not awake, I'll ask for the passphrase, start up, handle it. if there's no terminal to ask, I tell you straight:

```
hush agent is not running. Start it: hush up -d
```

no guessing. no improvising.

## commands

| | |
|---|---|
| `hush init` | generate your identity |
| `hush up [-d] [--ttl 1h]` | start the agent |
| `hush down` | zero the key, lights out |
| `hush hush <name>` | set up a new secret command |
| `hush <name> [args...]` | decrypt, template, execute, forget |
| `hush keyring {set,get,clear}` | manage the OS-keyring entry for the unlock backend |
| `hush oauth login <name>` | OAuth flow, register the result |
| `hush oauth get <name>` | print the current access token |
| `hush oauth refresh <name>` | force a refresh |
| `hush encrypt-value <str>` | encrypt one value, print it |
| `hush status` | what's running, what's available |

## the rules I keep

age identity stored as `[]byte`, zeroed on every exit path. passphrase buffer zeroed after use. socket is `0600`. hard-exit on TTL, I don't trust clients to tell me when to quit. daemon key transfer over `os.Pipe`, lives for a fraction of a second. OAuth refresh tokens encrypted on disk same as the rest; access tokens live in process memory only. stale sockets get cleaned up. professionals tidy after themselves.

one of me at a time: exclusive `flock` on `agent.pid`, held for life, kernel lets go when I do. the pid file stays put — it's the lock, not litter. if my refresh token gets rotated out from under me, I take the newer one off disk and move on.

(Go makes an immutable string copy of the passphrase I can't wipe. language limitation. I documented it. I ain't proud but I'm honest.)

## config

`~/.config/hush/hush.toml`:

```toml
ttl = "1h"
identity = "/custom/path/to/identity.age"
```

priority: CLI flags, then env (`HUSH_TTL`, `HUSH_IDENTITY`), then config, then defaults (30m). your word is final.

**directories** also come from env when set, in priority order:
`HUSH_CONFIG_DIR` / `HUSH_STATE_DIR` / `HUSH_RUNTIME_DIR` (hush-scoped,
used as-is), then `XDG_CONFIG_HOME` / `XDG_STATE_HOME` / `XDG_RUNTIME_DIR`
(append `/hush`), then the standard XDG defaults under `$HOME`. The
`HUSH_*` overrides exist so dev shells and embedded callers can pin every
singleton without colliding with the user's session-level XDG vars.

## unlock — passphrase, keyring, exec

the agent decrypts the on-disk identity at startup. how it gets the
passphrase is up to you:

```toml
[unlock]
method = "passphrase"   # default — TTY prompt (today's behavior)
```

```toml
[unlock]
method = "keyring"      # OS keyring: libsecret / Keychain / wincred

[unlock.keyring]
service = "hush"
account = "default"
```

```toml
[unlock]
method = "exec"         # any password manager via its CLI
exec   = ["pass", "show", "hush/passphrase"]
# exec = ["op",   "read", "op://Personal/Hush/passphrase"]
# exec = ["rbw",  "get",  "hush"]
```

seeding the keyring is a one-liner:

```
hush keyring set       # double-prompts, stores, wipes
hush keyring get       # ✓ present / ✗ not set (never prints the value)
hush keyring clear     # delete the entry
```

put it together with a long ttl and you type your passphrase once per
desktop session (or once per machine, if your keyring outlives reboots):

```toml
ttl = "168h"

[unlock]
method = "keyring"
```

headless machine without a Secret Service provider? use `method = "exec"`
with `pass` or `rbw` — no dbus dependency.

`hush status` prints the active method so you always know which mouth
is whispering the passphrase.

## compared to that other fella

| | hush | sops |
|---|---|---|
| size | **8 MB** | 69 MB |
| associates | age, toml | age, pgp, aws, gcp, azure, vault, grpc, protobuf, ... |
| encryption | per-value age | per-value AES with a data key |
| refresh | yes | no |
| disposition | quiet | loud |

sops does fine work. but it travels heavy.

## license

MIT. do what you want. just keep it quiet.

*🤫*
