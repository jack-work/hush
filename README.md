# 🤫 hush

*psst. c'mere.*

wanna hear a secret?

```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

didn't catch that? good. that's the idea.

your `.env` file's loungin' around in plaintext. your shell history's runnin' its mouth. your AI agent's scrolling past your API token in the chat like it's the morning paper. everybody's got a big mouth.

me? I hold secrets in memory, refresh the OAuth tokens that go stale, slip 'em where they gotta go, forget the rest. key's zeroed. socket's gone. I don't recall.

**9 MB.** [age](https://age-encryption.org) encryption, a unix socket, a little keyvault gated by your passphrase. door locked. `0600`. quiet as a church.

```
go install github.com/jack-work/hush@latest && hush init
```

## how it works

you give me a passphrase. I unlock your age identity (X25519, real cryptography), hold the private key in memory, zero the passphrase. then I sit on a unix socket and answer.

**static secrets** are age-encrypted per value, so git sees which key changed and not what:

```toml
token     = "AGE-ENC[YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgy...]"
client_id = "not-secret-plaintext"
```

when you run `hush brave "query"`, I decrypt, template into your shell command, execute, forget. the secret reaches that child process and nowhere else — not your history, not your environment, not the chat.

**OAuth tokens** are mine to keep current. log in once with `hush oauth login`, I renew the access token partway through its life and hand the live one over the socket to whoever asks.

## commands

| | |
|---|---|
| `hush init` | generate your identity |
| `hush up [-d] [--ttl 1h]` / `hush down` | start the agent / zero the key, lights out |
| `hush <name> [args...]` | decrypt, template, execute, forget |
| `hush secret new <name>` | scaffold a command and its first secret |
| `hush secret encrypt <str>` / `decrypt <str>` | one value, in or out |
| `hush secret seal [name]` | lock up plaintext you left lying about (bare: everywhere) |
| `hush oauth login\|get\|refresh\|list\|delete <name>` | tokens I keep fresh |
| `hush keyring set\|get\|clear` | the passphrase entry backing `method = "keyring"` |
| `hush status` | what's running, what's available |

## what's on disk

```
~/.config/hush/identity.age(.pub)          your key, passphrase-wrapped
~/.config/hush/hush.toml                   ttl, unlock method
~/.config/hush/commands/<name>/command.sh  template: {{.token}}, {{.Args}}
                        …/secrets.toml     key = "AGE-ENC[…]"
~/.local/state/hush/oauth/<name>.toml      tokens, encrypted at rest
```

## config

```toml
ttl = "168h"

[unlock]
method = "keyring"          # or "passphrase" (TTY), "exec", "auto"

[unlock.keyring]
service = "hush"
account = "default"

# method = "exec" runs any password manager and reads stdout:
# exec = ["pass", "show", "hush/passphrase"]
# exec = ["op", "read", "op://Personal/Hush/passphrase"]
```

priority: flags, then env (`HUSH_TTL`, `HUSH_IDENTITY`, `HUSH_CONFIG_DIR` / `HUSH_STATE_DIR` / `HUSH_RUNTIME_DIR`), then config, then XDG defaults. your word is final. the `HUSH_*` directory overrides let dev shells and embedded callers pin every singleton without colliding with your real one.

seed the keyring once (`hush keyring set`, double-prompts, never prints it) and with a long ttl you type your passphrase once a session. headless box with no Secret Service? `method = "exec"` needs no dbus. `hush status` always names the method in play.

## embedding me

three packages, and no more:

```go
client.New()          // talk to a running agent: Decrypt, Encrypt, OAuth*
managed.New(opts)     // embed me: your own identity, agent and dirs
config.Dirs{...}      // pin where all of it lives
```

everything else is `internal/`. if you can't import it, you weren't meant to.

## the rules I keep

identity stored as `[]byte`, zeroed on every exit path. passphrase buffer zeroed after use. socket is `0600`. hard-exit on TTL — I don't trust clients to tell me when to quit. daemon key transfer over `os.Pipe`, alive for a fraction of a second. refresh tokens encrypted on disk like everything else; access tokens live in memory only. no path in me ever writes a decrypted secret to a temp file.

one of me at a time: exclusive `flock` on `agent.pid`, held for life, kernel lets go when I do. the pid file stays put — it's the lock, not litter. if my refresh token gets rotated out from under me, I take the newer one off disk and carry on; if a rotation goes missing, I try its predecessor once before asking you to log in again.

(Go makes an immutable string copy of the passphrase I can't wipe. language limitation. I documented it. I ain't proud but I'm honest.)

## compared to that other fella

| | hush | sops |
|---|---|---|
| size | **9 MB** | 69 MB |
| associates | age, toml | age, pgp, aws, gcp, azure, vault, grpc, ... |
| refresh | yes | no |
| disposition | quiet | loud |

sops does fine work. but it travels heavy.

MIT. do what you want. just keep it quiet.

*🤫*
