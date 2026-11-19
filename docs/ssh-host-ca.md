# SSH host CA (`kind = "ssh-ca"`)

`hush cred serve` can hold an SSH host certificate authority. The CA private keys live only in the server's state,
age-encrypted to the config's recipient (`<state-dir>/ssh-ca/<name>.toml`); they are generated in memory and never
written in the clear. Two keys are kept: **current** signs, **next** is published early so every host trusts it
before it ever signs.

```toml
[instances.fleet-ssh-ca]
kind = "ssh-ca"
validity = "840h"                              # host cert lifetime, 1h..2160h (default 35 d)
grants_file = "/var/lib/band-grants/grants.json"   # default

[principals.onboardd]
users = ["onboardd"]
credentials = ["fleet-ssh-ca"]
```

## Routes (owner socket, or a principal socket granted the instance)

| Route | Does |
|---|---|
| `GET /ssh-ca/<name>/pub` | `{"current": "<pub>", "next": "<pub>"}` (`409 no_ca` before the first rotate) |
| `POST /ssh-ca/<name>/sign-host` `{"node", "public_key"}` | `{"certificate": "<cert line>"}`: a host cert, principal = the node name only, ed25519 host keys only |
| `POST /ssh-ca/<name>/rotate` | next becomes current, a new next is minted; with no state yet, mints both |

`rotate` needs a live consent grant `ssh-ca-rotate:<name>` for the calling principal (`owner` on the owner socket)
in `grants_file`: the row band-grants writes when an approver approves on `/grants/`. Expiry is checked at use.
`/cred/<name>` never serves an ssh-ca instance. Every sign and rotate writes an audit line (fingerprints, never keys).

## Why the principal is the node name only

Fleet nodes are reached as `127.0.0.1:<port>` through tunnels, and OpenSSH checks a host cert's principals against the
host name, not the port. An address principal would make one node's cert valid for every node; a tunnel that shifts
ports would then go unnoticed. Clients set `HostKeyAlias <node>` per host, so the check names the node.

## Rotation

1. Approve `ssh-ca-rotate:<name>` on `/grants/`; `POST .../rotate` (the old next, already trusted, becomes current).
2. Re-sign every host (`sign-host`); publish the new next to every client's trust.
3. Drop the old current from client trust once every host carries a cert from the new current.
