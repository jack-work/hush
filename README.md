# 🤫 hush

Keeps quiet. Keeps silent. *Hush hush.*

A secret-injecting command runner that doesn't make a peep. Your secrets stay encrypted on disk, decrypted only in memory, and injected into shell commands through Go templates. No cloud dependencies. No YAML cathedrals. No 69MB binary hauling half of AWS along for the ride.

**8MB.** That's it. Just [age](https://age-encryption.org) encryption and a unix socket. On the down low.

## What it does

hush holds your decrypted age identity in a short-lived agent process. When you run a command, it decrypts only the values you need, templates them into a shell script, executes it, and forgets everything. The agent zeros the key material and exits on a hard timer. No trace.

```
~/.config/hush/
├── identity.age           # passphrase-encrypted age private key
├── identity.age.pub       # public key (safe to share)
├── hush.toml              # optional config
└── commands/
    └── brave/
        ├── command.sh     # Go template: curl -H "Bearer {{.token}}" ...
        └── secrets.toml   # per-value encrypted TOML
```

Secrets on disk look like this:

```toml
token = "AGE-ENC[YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgy...]"
api_key = "AGE-ENC[c29tZXRoaW5nLWVsc2UuLi4...]"
client_id = "not-secret-plaintext"
```

Keys are visible. Values are locked. Plaintext values pass through. Git diffs show *which* key changed without leaking *what* changed. Don't tell nobody.

## Install

```bash
go install github.com/jack-work/hush@latest
```

## Quick start

```bash
# Generate your identity (prompts for passphrase)
hush init

# Bootstrap a command with one secret
hush hush brave
# Enter secret value: ••••••••••••

# Edit the command template
$EDITOR ~/.config/hush/commands/brave/command.sh

# Run it (starts agent automatically if needed)
hush brave "golang age encryption"
```

## Commands

| Command | What it does |
|---|---|
| `hush init` | Generate a passphrase-encrypted age identity |
| `hush up [-d] [--ttl 1h]` | Start the agent (foreground or daemon) |
| `hush down` | Stop the agent, zero the key |
| `hush status` | Show agent, identity, and command info |
| `hush hush <name>` | Bootstrap a new command with one secret |
| `hush <name> [args...]` | Run a command (decrypt → template → execute) |
| `hush encrypt <name>` | Encrypt plaintext values in secrets.toml |
| `hush encrypt-value <str>` | Encrypt a single value, print to stdout |
| `hush lock` | Encrypt all plaintext values across all commands |
| `hush edit <name>` | Decrypt to `$EDITOR`, re-encrypt on save |
| `hush help` | Show this menu with your available commands |

## How it works

**The agent** (`hush up`) prompts for your passphrase, decrypts your age identity, holds it in memory, and listens on a unix socket (`$XDG_RUNTIME_DIR/hush/agent.sock`, permissions `0600`). It accepts encrypted values over the socket and returns plaintext. Hard-exits when the TTL expires. Zeros the key on any exit path — TTL, SIGTERM, SIGINT. Doesn't whisper a word after that.

**The client** (`hush <cmd>`) reads `secrets.toml`, sends the raw values to the agent, gets back the decrypted map, renders `command.sh` as a Go template, and executes it via `sh -c`. If no agent is running and you're in an interactive terminal, it starts one for you. If you're not interactive (piped, cron, an AI agent calling you), it tells you to start one yourself:

```
hush agent is not running and no interactive terminal is available.

Start the agent manually from an interactive shell:

  hush up -d
```

**Template context:**

```
{{.token}}           secret from secrets.toml
{{.client_id}}       plaintext value from secrets.toml
{{index .Args 0}}    first extra CLI argument
{{.Cmd}}             the command name
```

## Security model

- Age identity stored as `[]byte`, explicitly zeroed on exit
- Passphrase buffer zeroed after decryption
- Unix socket created with `0600` permissions
- Agent hard-exits on TTL — does not trust clients to tell it when to stop
- Stale socket detection — connects to verify liveness, cleans up dead sockets
- Per-value encryption — no blob encryption, no data key, each value is independently age-encrypted
- The `string(passphrase)` conversion creates an immutable copy that can't be zeroed (Go limitation, documented in code)

## Config

`~/.config/hush/hush.toml` (optional):

```toml
ttl = "1h"
identity = "/custom/path/to/identity.age"
```

Priority: CLI flags → environment (`HUSH_TTL`, `HUSH_IDENTITY`) → config file → defaults (30m TTL).

## Compared to SOPS

| | hush | sops |
|---|---|---|
| Binary size | **8 MB** | 69 MB |
| Dependencies | age, toml | age, pgp, aws, gcp, azure, vault, grpc, protobuf, ... |
| Encryption | Per-value age | Per-value AES (age/kms/pgp for data key) |
| Secret format | Flat TOML | YAML/JSON/ENV/INI |
| Runtime | In-memory agent with TTL | Decrypt on every invocation |
| Use case | Inject secrets into commands | Encrypt files for storage |

sops is a fine tool for what it does. hush is for when you want to keep it quiet.

## License

MIT
