# 🤫 hush

*psst. c'mere. closer.*

wanna hear a secret?

```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

didn't catch that? good. that's the whole point.

see, the problem with secrets is everybody's got a big mouth. your shell history? talks. your `.env` file sitting in plaintext? sings like a canary. that CI pipeline printing debug logs? *fuggedaboutit.* whole world's full of loud programs that don't know when to keep quiet.

me? I'm hush. the quietest 8MB you'll ever meet. I hold your secrets in memory, slip 'em where they need to go, then forget I ever knew anything. you could subpoena me after my TTL expires. I got nothin'. the key's zeroed. the socket's gone. I was never here.

no cloud. no 69MB binary smuggling half of AWS in its trenchcoat. just [age](https://age-encryption.org) encryption and a unix socket with the door locked (`0600`, capisce?).

## how the arrangement works

you come to me once. give me a passphrase. I use it to unlock your age identity — that's an X25519 key pair, serious cryptography, not some Caesar cipher from a cereal box — and I hold the private half in memory. *only* in memory. I zero the passphrase the moment I'm done with it.

then you hand me your secrets file. each value is individually encrypted. not the whole file in a blob — each value, separately, with its own age ciphertext. the keys stay in plaintext so you can see the shape of things without seeing the things themselves:

```toml
token = "AGE-ENC[YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgy...]"
api_key = "AGE-ENC[c29tZXRoaW5nLWVsc2UuLi4...]"
client_id = "not-secret-plaintext"
```

git sees which key changed. git don't see what changed. that's need-to-know, and git don't need to know.

when you run a command, I decrypt the values, slide them into your shell template through a Go template engine, execute it, and that's that. the plaintext lives in memory for the blink of an eye. then it's gone and I don't remember a thing. don't ask me. I don't know nothin'.

## the setup

```bash
go install github.com/jack-work/hush@latest
```

```bash
# sit down, let's get acquainted
hush init

# you got something for me? I'll keep it safe.
hush hush brave

# write how you want it delivered
$EDITOR ~/.config/hush/commands/brave/command.sh

# say the word
hush brave "golang age encryption"
```

first time you come to me in a session, I'll ask for the passphrase. after that, I remember — for a while. thirty minutes by default. then I forget everything. you want longer, you tell me. you want shorter, wise choice.

## what I answer to

| | |
|---|---|
| `hush init` | first meeting. I generate your age identity, lock it with a passphrase. |
| `hush up [-d] [--ttl 1h]` | wake me up. I'll listen in the foreground or the back room. |
| `hush down` | I zero the key. close the socket. lights out. |
| `hush status` | I'll tell you if I'm awake, how long I got left, what commands you got. |
| `hush hush <name>` | bring me a new secret. I'll set up the whole arrangement. |
| `hush <name> [args...]` | the job. I decrypt, template, execute, forget. |
| `hush encrypt <name>` | you left something in plaintext? I'll lock it up for you. |
| `hush encrypt-value <str>` | one value. in, out, encrypted. quick and quiet. |
| `hush lock` | sweep the whole place. encrypt every plaintext value I can find. |
| `hush edit <name>` | I'll open it up for you in `$EDITOR`. when you close, I lock it back. |

## the family layout

```
~/.config/hush/
├── identity.age           # the key. passphrase-encrypted. I don't touch it without your say-so.
├── identity.age.pub       # the public half. give it to whoever you want.
├── hush.toml              # optional. tells me your preferences.
└── commands/
    └── brave/
        ├── command.sh     # the template. Go syntax: {{.token}}, {{index .Args 0}}
        └── secrets.toml   # the goods. AGE-ENC wrapped, per-value.
```

## the rules I live by

- your age identity is a `[]byte`. I zero every byte on exit. every exit. TTL, SIGTERM, SIGINT, don't matter.
- the passphrase buffer? zeroed the instant I'm done decrypting. (Go makes an immutable string copy I can't touch — it's a known limitation, I documented it, I'm not proud of it, but I'm honest about it.)
- the socket is `0600`. only you can talk to me.
- I hard-exit on TTL. I don't trust nobody to tell me when to quit — I tell myself.
- if I find a stale socket from some previous version of me that didn't clean up, I check if anyone's home, and if not, I clean it up myself. professionals clean up after themselves.
- daemon mode works by re-exec with the decrypted key passed through an `os.Pipe`. not a temp file. not an env var. a pipe that exists for a fraction of a second and then it's gone.

## the config

`~/.config/hush/hush.toml`:

```toml
ttl = "1h"
identity = "/custom/path/to/identity.age"
```

priority: what you tell me on the command line → environment variables → the config file → my own defaults. your word is final.

## compared to that other guy

| | hush | sops |
|---|---|---|
| size | **8 MB** | 69 MB |
| friends | age, toml | age, pgp, aws, gcp, azure, vault, grpc, protobuf, ... |
| encryption | per-value age | per-value AES with a data key |
| format | flat TOML | YAML/JSON/ENV/INI |
| runtime | in-memory agent, short fuse | decrypt from disk every time |
| personality | quiet | loud |

sops is a fine program. does good work. but it's got a lot of associates and it carries a lot of weight. me, I travel light.

## one last thing

I'm MIT licensed. do what you want. just keep it quiet.

*🤫*
