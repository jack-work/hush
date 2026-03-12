# 🤫 hush

*psst. c'mere.*

wanna hear a secret?

```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

didn't catch that? good. that's the idea.

your `.env` file's loungin' around in plaintext. your shell history's runnin' its mouth. your AI agent's scrolling past your API token in the chat like it's the morning paper. everybody's got a big mouth.

me? I hold secrets in memory, slip 'em where they gotta go, forget everything. key's zeroed. socket's gone. I don't recall.

**8MB.** just [age](https://age-encryption.org) encryption and a unix socket. door locked. `0600`. quiet as a church.

## get me

tired of your API tokens scrolling through the chat context? paste this into Claude Code, pi, or your favorite coding agent:

> `alright loudmouth, go install github.com/jack-work/hush@latest and call hush loudmouth over cli`

I'll take it from there. your agent never sees the secret.

also good for: vibe coding on a livestream without flashing your billing credentials to 10,000 (or 10) strangers.

## how it works

you give me a passphrase. I unlock your age identity (X25519, real cryptography), hold the private key in memory, zero the passphrase. each value in your secrets file is individually age-encrypted:

```toml
token = "AGE-ENC[YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgy...]"
client_id = "not-secret-plaintext"
```

keys visible. values locked. git sees which key changed, not what changed. need-to-know, and git don't need to know.

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
| `hush encrypt-value <str>` | encrypt one value, print it |
| `hush status` | what's running, what's available |

## the rules I keep

age identity stored as `[]byte`, zeroed on every exit path. passphrase buffer zeroed after use. socket is `0600`. hard-exit on TTL, I don't trust clients to tell me when to quit. daemon key transfer over `os.Pipe`, lives for a fraction of a second. stale sockets get cleaned up. professionals tidy after themselves.

(Go makes an immutable string copy of the passphrase I can't wipe. language limitation. I documented it. I ain't proud but I'm honest.)

## config

`~/.config/hush/hush.toml`:

```toml
ttl = "1h"
identity = "/custom/path/to/identity.age"
```

priority: CLI flags, then env (`HUSH_TTL`, `HUSH_IDENTITY`), then config, then defaults (30m). your word is final.

## compared to that other fella

| | hush | sops |
|---|---|---|
| size | **8 MB** | 69 MB |
| associates | age, toml | age, pgp, aws, gcp, azure, vault, grpc, protobuf, ... |
| encryption | per-value age | per-value AES with a data key |
| disposition | quiet | loud |

sops does fine work. but it travels heavy.

## license

MIT. do what you want. just keep it quiet.

*🤫*
