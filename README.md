# 🤫 hush

*psst. c'mere.*

wanna hear a secret?

```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

didn't catch that? good. that's the idea.

I started out as a guy with an [age](https://age-encryption.org) key and a unix socket, keeping your `.env` out of the chat. word got around. these days I hold the sign-ins. your laptop's API keys, the OAuth tokens that go stale every hour, the plan logins a whole box full of agents runs on. one small Go binary, about **12 MB**, does all of it. the refresh token stays with me. the access token goes to whoever's allowed, with a short life on it. ask me what I handed out yesterday and I'll tell you the name, the caller and the time. the token itself? I don't recall.

```
go install github.com/jack-work/hush@latest && hush init
```

## two jobs, one binary

| | the agent | the minter |
|---|---|---|
| runs as | you, on your own box | its own system user, `hush`, on a host |
| started by | `hush up`, or socket activation | `hush.service` (NixOS: `services.hush`) |
| holds | your age identity, sealed command secrets, OAuth pairs | plan sign-ins: ChatGPT, Copilot, Anthropic, any refresh-token OAuth, or a token another tool already keeps |
| answers | you, on `$XDG_RUNTIME_DIR/hush/agent.sock` | named uids, one socket per principal, `GET /cred/<name>` |
| hands out | a secret into one child process | a short-lived bearer and its expiry, never the refresh token |

they share nothing: no config, no socket, no keyring. same tradecraft, different clients.

## the agent: your secrets, your commands

you give me a passphrase, or tell me where to find it. I unlock your age identity (X25519, real cryptography), hold the private key in memory, zero the passphrase. then I sit on a socket and answer.

**static secrets** are age-encrypted per value, so git sees which key changed and not what:

```toml
token     = "AGE-ENC[YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgy...]"
client_id = "not-secret-plaintext"
```

when you run `hush brave "query"`, I decrypt, template into your command, execute, forget. the secret reaches that child process and nowhere else: not your history, not your environment, not the chat.

**shims** put a command under its real name. `hush shim install gh` drops a symlink in my shims dir; with that dir early on `PATH`, `gh pr list` runs through me, gets its credential, and execs the real `gh` with your arguments untouched. scripts that exec by name pick it up. an alias wouldn't. I strip the shims dir from the child's `PATH`, so the real tool never loops back to me.

**OAuth tokens** are mine to keep current. `hush oauth login` (authorization code) or `hush oauth device-login` once, and I renew the access token partway through its life and pass the live one to whoever asks on the socket.

**plain environment** a command needs to work at all goes in its spec's `[env]` table, so the knowledge travels with the command instead of being redeployed on every box. precedence and refusals: [docs/command-env.md](docs/command-env.md).

`hush doctor` tells you how each command gets its secrets and what to fix. `hush status` names what's running and which unlock method is in play.

## the minter: sign-ins for a whole host

put me on a box where agents work and nobody sits at the keyboard. I run as user `hush` (uid 476), state in `/var/lib/hush` (0700), one encrypted token file per instance, sealed to an age recipient. the identity reaches the unit alone, through systemd's `LoadCredential`.

| socket | who gets in | what it answers |
|---|---|---|
| `/run/hush/<principal>.sock` | that principal's users | `GET /cred/<name>`, only for the instances it was granted |
| `/run/hush/cred.sock` | `credUsers` | `GET /cred/<name>` for every instance |
| `/run/hush/drop.sock` | `dropUsers` | start and finish a sign-in, ask for a refresh. replies carry a URL or a device code. never a token |
| `/run/hush/admin.sock` | the `hush` uid | `GET /status`, refresh, sign-in, `GET /cred/<name>` |

**what I mint for.** `chatgpt`, `copilot` (GitHub device flow, then the Copilot token), `anthropic` (pinned to the Max grant), `refresh_token` (any OAuth app you name: client, token URL, scopes) and `exec`, a credential another tool already holds: I run its command, it prints `{"token", "expires_at"}`, I serve that until it's about to go. exit 3 means "sign in again".

**how I hand it out.** a bearer leaves me with at least 30 seconds of life on it, or I refresh first. ten callers at once get one refresh between them, and after a failure I wait before trying again. on stop I drain: no refresh in flight gets cut in half, and a rotated pair hits the disk before anybody sees it ([docs/refresh-drain.md](docs/refresh-drain.md)).

**who I talk to.** every socket is `0600 hush:hush` plus one ACL entry per allowed user, and I check the caller's uid again with `SO_PEERCRED`. groups grant nothing. a principal socket answers anything but `GET /cred/<name>` with a 404. turn on `audit` for an instance and I write one line per request, served or refused: credential, principal, uid, status. never the token.

**who I call.** the egress fence (nftables, table `inet hush`) holds my uid to DNS and the token endpoints of the instances you declared. nothing else gets out.

**one of me.** a state lock refuses a second minter on the same state, because two minters holding one refresh token race to rotate it and the loser's copy is dead.

```nix
imports = [ hush.nixosModules.hush ];
services.hush = {
  enable = true;
  recipient = "age1...";                       # sign-ins are sealed to this
  identityFile = "/var/lib/hush/identity.age"; # handed to the unit alone (LoadCredential)
  instances.copilot-work = { kind = "copilot"; clientId = "Iv1...."; scopes = "read:user"; audit = true; };
  principals.agents = { users = [ "figaro" ]; credentials = [ "copilot-work" ]; };
  credUsers = [ ];                             # no socket that serves every instance
  dropUsers = [ "you" ];                       # who may sign it in
};
```

signing in, status and moving a host off the old `services.hush-cred` name: [docs/hush-system-service.md](docs/hush-system-service.md). per-kind notes: [ChatGPT](docs/chatgpt-credentials.md), [Anthropic](docs/anthropic-credentials.md).

## what I keep quiet about, and what I don't

| I keep out of | how |
|---|---|
| your shell history, environment, chat logs | secrets go into one child process, templated at exec |
| git | values encrypted one by one; the keys and structure stay readable |
| other users on the box | `0600` sockets, ACL per user, peer uid checked on every request |
| a caller's hands, past the access token | refresh tokens never leave the minter; bearers are short-lived |
| the rest of the internet | the minter's uid reaches only its token endpoints |

| I can't help you with | |
|---|---|
| root on the box | root reads my memory. nobody keeps secrets from the landlord |
| a caller I was told to trust | once the bearer's handed over, it's theirs until it expires |
| a token after it leaves | revoke at the provider, or rotate |
| Go's string copy of your passphrase | the runtime makes one I can't wipe. documented. I ain't proud, but I'm honest |

## commands

| | |
|---|---|
| `hush init` | generate your identity |
| `hush reset` | passphrase lost: delete the identity AND everything sealed to it, then init again |
| `hush up [-d] [--ttl 1h]` / `hush down` | start the agent / zero the key, lights out |
| `hush <name> [args...]` | decrypt, template, execute, forget |
| `hush secret new <name>` | scaffold a command and its first secret |
| `hush secret encrypt <str>` / `decrypt <str>` | one value, in or out |
| `hush secret seal [name]` | lock up plaintext you left lying about (bare: everywhere) |
| `hush shim install\|ls\|rm\|dir` | run brokered commands under their real names |
| `hush oauth login\|device-login\|register\|get\|refresh\|list\|delete <name>` | tokens I keep fresh |
| `hush keyring set\|get\|clear` | the passphrase entry backing `method = "keyring"` |
| `hush install-units` | let systemd start me on demand, so nobody has to |
| `hush doctor [--migrate]` | how each command gets its secrets, and what to change |
| `hush status` / `hush version` | what's running, what's available, which build |
| `hush cred serve` / `hush cred login <name>` | the minter, and a terminal sign-in with the minter stopped |

## nobody has to start me

on a systemd box, don't. install the units once:

```
hush install-units
```

that writes `hush-agent.socket` and `hush-agent.service` into your user units and arms the socket. the first client that touches `$XDG_RUNTIME_DIR/hush/agent.sock` makes systemd start me; I adopt the descriptor it bound (`LISTEN_FDS`), so that client waits in the backlog instead of getting the door slammed. I unlock by whatever `unlock.method` you named. TTL runs out, I exit, the socket re-arms. no login shell, nothing in your profile.

`hush up` still works on boxes without the units. what I won't do is bind over a socket that's already listening: that one belongs to the socket unit, and unlinking it would leave systemd holding an inode nobody can reach. so I refuse and tell you which door to use.

on NixOS the same two units come off the flake:

```nix
imports = [ hush.nixosModules.default ];
services.hush-agent.enable = true;
```

## what's on disk

```
~/.config/hush/identity.age(.pub)          your key, passphrase-wrapped
~/.config/hush/hush.toml                   ttl, unlock method
~/.config/hush/commands/<name>/command.sh  template: {{.token}}, {{.Args}}
                        …/command.toml     shape: exec, args, env, secrets, oauth
                        …/secrets.toml     key = "AGE-ENC[…]"
~/.local/state/hush/oauth/<name>.toml      tokens, encrypted at rest

/etc/hush/config.toml                      minter: recipient, instances, principals
/var/lib/hush/                             minter: one sealed token file per instance
```

## config

```toml
ttl = "168h"

[unlock]
method = "keyring"          # or "passphrase" (TTY), "exec", "file", "auto"

[unlock.keyring]
service = "hush"
account = "default"

# method = "exec" runs any password manager and reads stdout:
# exec = ["pass", "show", "hush/passphrase"]
# exec = ["op", "read", "op://Personal/Hush/passphrase"]

# method = "file" reads the passphrase from a file only you can read
# (mode 0600 or tighter, or I refuse it):
# file = "/home/you/.config/hush/passphrase"
```

priority: flags, then env (`HUSH_TTL`, `HUSH_IDENTITY`, `HUSH_CONFIG_DIR` / `HUSH_STATE_DIR` / `HUSH_RUNTIME_DIR`), then config, then XDG defaults. your word is final. the `HUSH_*` directory overrides let dev shells and embedded callers pin every singleton without colliding with your real one.

the agent I start in the background leads its own session and writes its stderr to `agent.log` in my state dir. where a systemd user manager answers from a directory you own alone, I also move it into a transient scope of its own, `hush-agent-<instance>-<pid>.scope`, so the unit that started it doesn't take it down when it ends. `HUSH_NO_AGENT_SCOPE=1` keeps it in its spawner's cgroup; tests set it.

seed the keyring once (`hush keyring set`, double-prompts, never prints it) and with a long ttl you type your passphrase once a session. headless box with no Secret Service? `method = "exec"` needs no dbus, and `method = "file"` needs no helper either.

## embedding me

three packages, and no more:

```go
client.New()          // talk to a running agent: Decrypt, Encrypt, OAuth*
managed.New(opts)     // embed me: your own identity, agent and dirs
config.Dirs{...}      // pin where all of it lives
```

everything else is `internal/`. if you can't import it, you weren't meant to.

## the rules I keep

identity stored as `[]byte`, zeroed on every exit path. passphrase buffer zeroed after use. sockets are `0600`. hard exit on TTL: I don't trust clients to tell me when to quit. daemon key transfer over `os.Pipe`, alive for a fraction of a second. refresh tokens encrypted on disk like everything else; access tokens live in memory. no path in me writes a decrypted secret to a temp file.

one of me at a time: exclusive `flock` on `agent.pid` for the agent, a state lock for the minter, held for life, and the kernel lets go when I do. if my refresh token gets rotated out from under me, I take the newer one off disk and carry on; if a rotation goes missing, I try its predecessor once before asking you to sign in again.

the refusals have tests that prove I refuse. the minter's sockets, fence and host moves are checked in NixOS VM tests (`nix/cred-test.nix`, `nix/cred-rename-test.nix`).

## compared to that other fella

| | hush | sops |
|---|---|---|
| size | **12 MB** | 52 MB |
| associates | age, toml | age, pgp, aws, gcp, azure, vault, grpc, ... |
| refresh | yes | no |
| serves a live token to other users | yes | no |
| disposition | quiet | loud |

sops does fine work, and static secrets in a repo are its beat. but it travels heavy, and it doesn't stay up nights keeping a token warm.

MIT. do what you want. just keep it quiet.

*🤫*
