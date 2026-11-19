# Identity contracts

hush is the certificate authority, the workload agent and the client library for one trust domain. These are the three contracts other programs build on: the SVID shapes, the trust bundle, and the workload socket. They are frozen: a change here is a breaking change and needs a new version path (`/v2/`, a new bundle `use`), not an edit.

The shapes follow SPIFFE (X.509-SVID, JWT-SVID, SPIFFE Trust Domain and Bundle). A stock SPIFFE verifier accepts what hush issues; hush checks that in its tests against go-spiffe, never at run time.

The packages are importable (`github.com/jack-work/hush/spiffeid`, `bundle`, `svid`, `ca`), so a program can link hush in instead of shelling out to it. figaro does this: one figaro binary can be hush, the angelus and the valet.

## 1. Identities

A SPIFFE ID is `spiffe://<trust domain>/<path>`.

- Trust domain: the troupe name, lowercase letters, digits and inner hyphens, at most 63 (as figaro's `troupe.ValidName`).
- Path: segments of `A-Z a-z 0-9 . - _`, no empty segment, no `.` or `..`. No query, fragment, port or user info. At most 2048 bytes in all.

| identity | path | issued to |
|---|---|---|
| node | `/node/<node>` | a machine, its hush and its figaro node door |
| unit | `/node/<node>/unit/<systemd unit>` | a process attested to a system unit on that node |
| instance | `/node/<node>/unit/<template>.<type>/<instance>` | a process in an instanced unit (`figaro-valet@gluck.service` is `/unit/figaro-valet.service/gluck`); an instance that is not a plain segment falls back to the uid identity |
| uid | `/node/<node>/uid/<uid>` | a process attested only by its uid |
| sandbox | `/node/<node>/unit/<template>.service/<name>` | a process in the payload of a sandbox machine (section 1.1); the instance form, with the machine's `-g<generation>` stripped |
| figaro | `/node/<node>/figaro/<aria id>` | a figaro, when the node's figaro vouches for it |

A unit identity goes only to a caller whose uid is the only uid running in that unit's cgroup tree; a user that `su`s inside a root unit, or any process in a unit that mixes uids, gets its uid identity instead.

Every workload identity sits under the node that issued it. A node's intermediate signs only its own subtree, and a node's JWT key speaks only for its own subtree; hush's verifier refuses an SVID whose path is outside `/node/<issuer's node>/`. That scoping is enforced by hush's verifier (`svid`), not by the PKI: X.509 name constraints cannot constrain URI paths, so a stock SPIFFE verifier would accept a compromised node's SVID for another node. Verify with `svid` wherever the node matters.

A unit identity is held by a uid: any process of that uid that can ptrace the unit (kernel.yama.ptrace_scope 0) can act as it. Run units that hold identities as their own uid (DynamicUser).

### 1.1 Sandbox identities (policy `node+machines`)

A sandbox is a systemd-nspawn machine run by a template unit, `/machine.slice/<template>@<name>-g<generation>.service`, in a fixed user-namespace range. With `hush workload serve --policy node+machines --machines <file>`, a caller gets `/node/<node>/unit/<template>.service/<name>` when all of these hold:

1. its pidfd is alive after the reads;
2. its cgroup is under `<unit>/payload/` (never `supervisor` or `.control`), and systemd-machined holds machine `<name>-g<generation>` with that unit (asked over D-Bus, not inferred from the cgroup);
3. the machine leader's `uid_map` is exactly one range, `0 <base + k*size> <size>`, where `k` is the sandbox's in the map;
4. the caller's uid, and the uid of every live process under `<unit>/payload/`, lies in that range;
5. `<name>` is in the map.

The map file: `{"template", "base", "size", "machines": {"<name>": {"id", "k"}}}`; a name may not end in `-g<digits>`, and no two names share a `k`. A caller in a machine unit of the map's template that fails any rule is refused (`403 unattested`), never given a uid identity; every other caller is policy `node`'s. The identity is keyed on the unit name and survives rebuilds (a new generation) and restarts; the uid range is a cross-check, because a retired sandbox's `k` is reused by the next one.

## 2. Keys and certificates

```
root (Ed25519, offline)                    CN "figaro troupe <td>", CA, path len 1, 2026..2126
└── node intermediate (Ed25519, per node)  CN "figaro troupe <td> node <node>", serialNumber <node>, CA, path len 0,
    │                                      permitted URI domain <td>, 1 year
    ├── node leaf                          URI spiffe://<td>/node/<node>, server+client auth, 7 days (1 to 30)
    └── X.509-SVID                         URI spiffe://<td>/node/<node>/..., server+client auth, 1 hour (5 minutes to 24 hours)
```

The root certificate is a function of the trust domain and the root key alone (serial and key id from SHA-256 of `<td>\0<public key>`, fixed validity), so hush and figaro derive byte-identical roots: the move from figaro's troupe to hush keeps every certificate already issued.

X.509-SVID leaves: exactly one URI SAN, not a CA, key usage digital signature only, `NotBefore` 5 minutes back for clock skew, `NotAfter` never past the issuer's. Keys: Ed25519 or ECDSA P-256.

JWT-SVID: compact JWS, `alg` `ES256`, `typ` `JWT`, `kid` `<node>:<key hash>` naming the signing key in the bundle and the node it speaks for. Claims `sub` (the SPIFFE ID, under `/node/<node>/`), `aud` (one or more, never empty), `exp`, `iat`. Signatures are low-s. Lifetime 5 minutes (at most 1 hour). A verifier refuses any other `alg`, a `kid` with no node or a `sub` outside it, a high-s signature, an audience it is not in, an expired token (no leeway beyond 30 seconds), an `exp` more than an hour out, and an `iat` in the future.

SSH user certificate: OpenSSH user cert, key id the SPIFFE ID, principals as granted, `ValidAfter` 5 minutes back, lifetime 10 minutes (at most 24 hours), no extensions but `permit-pty`.

## 3. Trust bundle

JSON, a JWK Set as in the SPIFFE bundle format:

```json
{
  "spiffe_sequence": 7,
  "spiffe_refresh_hint": 300,
  "keys": [
    {"use": "x509-svid", "kty": "OKP", "crv": "Ed25519", "x": "<b64url>", "x5c": ["<b64 DER of the root>"]},
    {"use": "jwt-svid", "kid": "<kid>", "kty": "EC", "crv": "P-256", "x": "<b64url>", "y": "<b64url>"}
  ]
}
```

- `x509-svid` keys carry exactly one certificate, a CA: the troupe root. Intermediates travel in the SVID's chain, never in the bundle.
- `jwt-svid` keys carry a `kid` of the form `<node>:<key hash>`, unique in the bundle.
- `spiffe_sequence` only grows. A client keeps the highest it has seen and refuses an older bundle.
- Unknown `use` values are skipped, so a later key type is not a break.

## 4. The workload socket

HTTP/1.1 over a unix socket. JSON in and out. No credentials on the wire: hush identifies the caller from the socket (peer pidfd, its cgroup, its uid) and refuses it if they disagree.

Path: `$HUSH_WORKLOAD_SOCKET`, else `/run/hush/workload.sock` (system hush), else `$XDG_RUNTIME_DIR/hush/workload.sock`.

| call | body | answer |
|---|---|---|
| `POST /v1/x509-svid` | `{"csr": "<PEM CSR>"}` | `{"spiffe_id", "chain": "<PEM leaf then intermediate>", "expires_at", "renew_after"}` |
| `POST /v1/jwt-svid` | `{"audience": ["..."]}` | `{"spiffe_id", "token", "expires_at"}` |
| `GET /v1/bundle` | | the bundle of section 3 |

- The private key never leaves the caller: it sends a CSR, hush ignores everything in it but the public key and fills in the identity it attested.
- `renew_after` is two thirds into the lifetime. A client renews then, and on any `403`.
- Errors: `{"error": "<code>", "reason": "<text>"}` with `400 bad_request`, `403 unattested` (the caller could not be tied to an identity), `403 not_granted`, `503 unavailable` (no intermediate, or it expired). Clients fail closed on every error.
