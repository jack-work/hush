---
name: command-env
description: The [env] table in command.toml. Plain non-secret environment a command carries with it, its precedence against inherited and credential environment, and every value hush refuses. Read before adding [env] to a command or changing childEnv.
---

# [env]

A command's compatibility facts belong to the command, not to the box it runs
on. `[env]` is where they go.

```toml
description = "garage S3 on spain"
exec = "/usr/bin/aws"
args = ["--endpoint-url", "https://s3.kelliher.info", "--region", "spain"]

[env]
AWS_REQUEST_CHECKSUM_CALCULATION = "WHEN_REQUIRED"
AWS_RESPONSE_CHECKSUM_VALIDATION = "WHEN_REQUIRED"

[secrets]
access_key_id = "AWS_ACCESS_KEY_ID"
secret_access_key = "AWS_SECRET_ACCESS_KEY"
```

That is the motivating case. awscli 2.23 began sending CRC checksums that
Garage rejects, and the two variables above turn them off. Before `[env]` they
lived in every user's `~/.aws/config`: a per-machine edit, redone on each new
box, describing a property of one command. In the spec they travel with it.

Values are literal. No template, no shell, no reference to `secrets.toml`.

## Precedence

The child's environment is assembled in one pass, lowest authority first. A
name claimed by a later layer is **removed** from the earlier one rather than
appended after it, so the environment names each variable exactly once and
nothing depends on `os/exec`'s duplicate-key rule.

| Layer | Source | Beats |
|---|---|---|
| 1 | inherited `os.Environ()` | nothing |
| 2 | `PATH`, with the shims directory stripped | the inherited `PATH`, always |
| 3 | `[env]` | the inherited value of the same name |
| 4 | `[secrets]` and `[oauth]` | unreachable, see below |

Layer 3 beating layer 1 is the point of the feature. A command that declares a
compatibility flag must get it whatever the caller happened to export.

Layer 4 never has to beat anything, because a collision between `[env]` and
`[secrets]` or `[oauth]` is refused at load. Precedence would be the wrong
answer there: three tables quietly fighting over one variable is a failure you
cannot see in the child, and a plaintext value shadowing a credential is the
one direction that must not be possible by accident.

## Refusals

All are checked by `Spec.Validate`, which runs in `LoadSpec`, so a bad spec
fails before the agent is asked for anything.

| Condition | Why |
|---|---|
| name outside `[A-Za-z_][A-Za-z0-9_]*` | not an environment variable name |
| name also in `[secrets]` or `[oauth]` | see above |
| `PATH` | hush strips the shims directory from it; restoring it lets a brokered command re-enter hush until the process table gives out |
| `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH` | they choose which code the child runs |
| name containing `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE`, `TOKEN`, `CREDENTIAL`, `PRIVATE_KEY`, `API_KEY`, `APIKEY`, `ACCESS_KEY` | that belongs in `[secrets]` or `[oauth]` |
| value containing `AGE-ENC[` | an encrypted value in the wrong table; `secrets.toml` is where hush decrypts |
| value containing a NUL byte | cannot be passed to `execve` |

## Why names are checked and values are not

A value heuristic cannot do the job it appears to do.

| | name check | value check |
|---|---|---|
| catches a misplaced long token | yes, by its name | sometimes |
| catches `PASSWORD = "hunter2"` | yes | no, it looks like a word |
| false positives | `SSH_AUTH_SOCK` survives, the word list is narrow | any opaque identifier: a bucket name, a user agent, a region |
| what it promises | that the obvious mistake is loud | that the table is safe, which it is not |

The last row is the real reason. `command.toml` is plaintext on disk beside the
encrypted `secrets.toml`, readable by anything that can read the directory, and
typically in git. Nothing hush checks changes that. A value filter would invite
the belief that `[env]` is screened, and a screened-looking place is exactly
where someone will eventually put a token. The boundary is the file, not the
filter: the name check is a typo catcher, announced as one.

`AGE-ENC[` is the exception because it is unambiguous. A value in that shape is
not a judgement call, it is a secret in the wrong table, and hush can say so.

## Visibility

`hush doctor` lists the plain env a command sets, next to how its credentials
are delivered, so reviewing what reaches a child does not mean opening the
spec:

```
ok   files          exec    runs /usr/bin/aws directly, no interpreter
                           plain env set by the spec: AWS_REQUEST_CHECKSUM_CALCULATION, AWS_RESPONSE_CHECKSUM_VALIDATION
```

## Code

| Where | What |
|---|---|
| `internal/cli/spec.go` | `Spec.Env`, `validateEnv`, `PlainEnv` |
| `internal/cli/exec.go` | `childEnv`, the one place the layers are assembled |
| `internal/cli/doctor.go` | `envFindings` |
| `e2e/env_test.go` | precedence and refusals through the real binary |
