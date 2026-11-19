# hush roadmap

hush is one small Go binary that keeps a machine's credentials, signs its users in, and serves short-lived tokens to the processes allowed to have them. Two plans now drive it. This file merges them into one list, so that each item has one owner and one issue.

- **sandbox-identity**: hush as the workload-identity agent for a pool of sandboxes (SPIFFE/SPIRE-style). Every sandbox gets one short-lived identity, and a gateway on its node trades that identity for real tokens under timed grants.
- **deployment-modes**: hush as a system service on each machine, a drop box for sign-ins and secrets, and federation between machines (figaro's `docs/proposals/deployment-modes`).

Every item below has a claim issue, labelled with the plan it comes from (`system:sandbox-identity`, `system:deployment-modes`, or both where the two plans asked for the same thing). Claim an item on its issue before starting it. Work on hush is paused until this file lands.

## Where hush is today

Shipped and merged on this repository:

- v0.15 to v0.17: the system minter, principals, the `exec` kind, `/status`, Copilot remote sign-in, the Anthropic Max sign-in, `oauth --timeout`, `services.hush` as a system service, the drop box (`drop.sock`: sign-in plus `POST /refresh`), the admin socket.
- #8: the README, rewritten to say what hush is now.
- #11: one consent check (`authorizeCred`) for every gated credential route, with grants read on each use.
- #12: tests for the owner `POST /refresh` route.
- #13: a systemd `LoadCredential` socket, so a granted unit gets its token as a systemd credential.

In review: #10 (stale episodes on `/status`) and #14 (the systemd socket goes through the consent check).

## Design rules

- One binary, no new daemon per feature, fast start.
- Table tests and shared fixtures, not copied setup. Search the repository before adding a helper.
- A negative test for every refusal.
- Tests run in the repository's nix devShell before a merge is asked for.
- Tokens never enter a sandbox. A sandbox holds only its own short-lived identity.
- Fleet certificates (SSH, web and service, sandbox identities) are signed by an external CA ([step-ca](https://smallstep.com/docs/step-ca/)); hush is its client. The one exception is figaro federation, which keeps its own CA (the troupe CA), moving into hush.

## Items

### Credential service

| item | what | proof | plan | status |
|---|---|---|---|---|
| Stale episodes (#15) | A credential that needs a new sign-in shows as stale on `/status`, from its first stale answer; the episode survives restarts and ends on confirmed recovery. An alert fires once per episode. | restart before first fetch keeps the episode; stale, success, stale gives two episodes | sandbox-identity | #10, fixing review findings |
| Systemd socket consent (#16) | The systemd credential socket grants through `authorizeCred` (consent to `systemd:<unit>`); oversized grants file refused. | ungranted unit refused; oversize refused | sandbox-identity | #14, in review |
| Templates and families (#17) | `?template=` and credential families; a node-to-node path for families served by another machine. | conformance per row against the previous minter | sandbox-identity | not started |
| Sign-in deadline (#18) | A deadline for browser (SPA) sign-ins, then `503 credential_stale`; an auth-code login. | deadline gives 503; login completes | sandbox-identity | not started |
| `hush login` client (#19) | One client for sign-ins: talks to the drop box, and runs an `exec` row's declared login (for example `az`, `gh`). | exit 3 prints the hint; the login runs once | both | not started |
| `PUT /secret` (#20) | Push a static secret into the drop box (write-only). | written secret is served to its principal; nobody can read it back through the drop box | deployment-modes | designed |
| Audit (#21) | One JSON line per fetch, attest, issue, grant decision and login (identity, machine, grant, row, outcome; never a token or key), to the journal. | redaction test | sandbox-identity | not started |
| Unlock without typing (#22) | The machine's hush starts after a reboot with no passphrase: its identity is sealed with `LoadCredentialEncrypted` (systemd's host key). | restart serves with no prompt; the sealed file copied elsewhere fails | sandbox-identity | not started |
| Retire `services.hush-cred` (#23) | Remove the one-release alias once every consumer uses `services.hush`. | evaluation fails on the old name with a pointer to the new one | deployment-modes | waits on consumers |
| Docs nit (#24) | The deferred review note in `docs/hush-system-service.md`. | doc reads true | deployment-modes | open |

### Workload identity

| item | what | proof | plan | status |
|---|---|---|---|---|
| Workload attestor (#25) | On a sandbox's workload socket, hush takes the peer as a pidfd (`SO_PEERPIDFD`, never a bare pid), reads its cgroup, maps it to the sandbox's systemd/nspawn unit and then to its identity, and requires the peer's uid to agree. An aria-level claim needs a second fact from figaro's box door. It then issues an X.509 SVID (10 minutes, renewed at 2/3) through the external CA. Interface: `POST /v1/attest` on a unix socket, `200 {spiffe_id, identity, unit, uid, expires_at}` or `403 {error: unattested, reason}`; clients fail closed. | refused: bare pid, exited pid, wrong cgroup, uid/unit disagree, unknown unit, retired identity, pid reuse, aria not in that sandbox, CSR SAN not the attested id; two sandboxes get distinct ids | both (the deployment-modes "local identity" is the same design) | not started |
| Gateway attest path (#26) | The node gateway passes its caller's pidfd to hush over a unix socket (HTTP over the socket); hush runs the same attestor. `HTTPS_PROXY` just works from inside a sandbox. | unattested peer, another sandbox's pidfd, endpoint/identity mismatch refused | sandbox-identity | not started |
| Timed grants and exchange (#27) | A grant is `{subject (SPIFFE id or prefix), dest host[:port], methods, path prefix, credential row, not_before, expires, approved_by}`, checked through `authorizeCred`. `POST /v1/exchange` returns the real token to the gateway, never to the sandbox. Admin revoke: a revoked grant stops the next exchange. | refused: no grant, expired, not yet valid, dest/method/path outside, another identity's grant, revoked | both (deployment-modes admin revoke folded in) | not started |
| Federation (#28) | figaro federation: an upstream hush serves the machines' hushes over mTLS signed by the troupe CA, which moves into hush (`services.hush.upstream` on a machine, `serveNodes` upstream; troupe root on offline media). It does not wait on, or block, the sandbox-identity gateway, which uses the external CA. Goal: merge the two into one system later. | another machine's cert, a subject from another machine, an expired cert refused; upstream down gives 502 and no cached secret | deployment-modes | not started; claimed by deployment-modes |
| SSH user certificates (#29) | hush issues an attested workload a 10-minute OpenSSH user certificate from the external CA; the git server trusts that CA, with a short principal per identity. | expired cert, other CA, principal not granted, static key after migration refused | sandbox-identity | not started |
| Per-aria identity (#30) | An aria's identity becomes unforgeable inside a shared sandbox once each aria runs under its own uid. | aria A's uid cannot get aria B's SVID | sandbox-identity | waits on figaro |

### Out of hush

- The SSH host CA moves to the external CA (draft #9 will close; its negative tests become that CA's acceptance tests).
- Static machine secrets stay with sops-nix.

## Decisions and open questions

**(a) Federation CA: DECIDED.** figaro federation keeps its separate CA (the troupe CA, moving into hush, iterated by deployment-modes). The external CA stays the CA for SSH, web and service certificates, box CAs and sandbox identities. Neither blocks the other; the goal is to merge federation and the fleet system into one later.

**(b) Canonical repository.** #8 and #11 to #13 merged here on GitHub. A second, self-hosted copy of hush is still at v0.17.0 (2bdde24). Decide which one is canonical and mirror the other from it.
