# hush roadmap

hush is one small Go binary that keeps a machine's credentials, signs its users in, issues workload identities, and serves short-lived tokens to the processes allowed to have them. Two plans drive it, and this file merges them into one list, so that each item has one owner and one issue.

- **sandbox-identity**: hush as the identity and credential service behind a pool of sandboxes. Each sandbox holds one short-lived identity and never a real token; one outbound gateway turns that identity into real credentials.
- **deployment-modes**: hush as a system service on each machine, the troupe CA, a drop box for sign-ins and secrets, and federation between machines (figaro's `docs/proposals/deployment-modes`).

Every item has a claim issue, labelled with the plan it comes from (`system:sandbox-identity`, `system:deployment-modes`, or both). Claim an item on its issue before starting it.

## Where hush is today

- v0.15 to v0.17: the system minter, principals, the `exec` kind, `/status`, Copilot remote sign-in, the Anthropic Max sign-in, `services.hush` as a system service, the drop box, the admin socket.
- #8: the README. #11 and #14: one consent check (`authorizeCred`) for every gated credential route. #12: tests for owner `POST /refresh`. #13: a systemd `LoadCredential` socket. #10: stale episodes on `/status`.
- v0.18.0 (#34): hush is the troupe CA and a SPIFFE-style workload agent: frozen contracts in [identity-contracts.md](identity-contracts.md), the CA core (root, per-machine intermediates, X.509-SVIDs, JWT-SVIDs, OpenSSH user certificates), the trust bundle, and the workload socket with pidfd + cgroup + uid attestation.

## Architecture

- **Identity.** Workload identities are hush's own SVIDs under the troupe CA, as [identity-contracts.md](identity-contracts.md) defines. A sandbox gets its identity from the workload socket of its machine's hush.
- **External CA.** [step-ca](https://smallstep.com/docs/step-ca/) signs only SSH host certificates and web, service and box TLS. It does not sign workload identities.
- **One outbound gateway.** A single gateway carries every outbound call from a sandbox, at explicit endpoints that clients are configured to use; nothing is intercepted. Per request it verifies the caller's SVID, checks the caller's group membership in [Kanidm](https://kanidm.com/), and asks hush for the real secret. hush stamps and forwards nothing; it builds no gateway.
- **Grants.** Kanidm group membership says who may use a service; hush holds the time limit of each grant, since Kanidm has no timed membership. Both must allow.
- **Secrets.** The root hush keeps refresh tokens. Read-only replicas on the gateway machines hold only the access tokens that gateway may use.
- **The admin's store CLI.** The admin stores a credential with one command, authenticated by a Kanidm passkey.

## Design rules

- One binary, no new daemon per feature, fast start.
- Table tests and shared fixtures, not copied setup. Search the repository before adding a helper.
- A negative test for every refusal.
- Tests run in the repository's nix devShell before a merge is asked for.
- Tokens never enter a sandbox. A sandbox holds only its own short-lived identity.
- The contracts in identity-contracts.md are frozen: a change is a new version path, not an edit.

## Items

### Credential service

| item | what | proof | plan | status |
|---|---|---|---|---|
| Templates and families (#17) | `?template=` and credential families; a machine-to-machine path for families served elsewhere. | conformance per row against the previous minter | sandbox-identity | not started |
| Sign-in deadline (#18) | A deadline for browser (SPA) sign-ins, then `503 credential_stale`; an auth-code login. | deadline gives 503; login completes | sandbox-identity | not started |
| Store CLI (#19) | `hush cred login <n>`: the admin authenticates to Kanidm with a passkey (PKCE, public client), the root hush checks the admin group, the credential's own login runs (device code, browser, or an `exec` row's login), and the result is stored in the root hush. Covers the drop-box login client. | refused: no Kanidm token, a token without the admin group, an expired token, a store sent to a replica | both | not started |
| `PUT /secret` (#20) | Push a static secret into the drop box (write-only). | written secret served to its principal; never readable back through the drop box | deployment-modes | designed |
| Audit (#21) | One JSON line per fetch, issue, grant decision and login (identity, machine, grant, row, outcome; never a token or key), to the journal. | redaction test | sandbox-identity | not started |
| Unlock without typing (#22) | The machine's hush starts after a reboot with no passphrase: its keys are sealed with `LoadCredentialEncrypted` (systemd's host key). | restart serves with no prompt; the sealed file copied elsewhere fails | sandbox-identity | not started |
| Retire `services.hush-cred` (#23) | Remove the one-release alias once every consumer uses `services.hush`. | evaluation fails on the old name with a pointer to the new one | deployment-modes | waits on consumers |
| Docs nit (#24) | The deferred review note in `docs/hush-system-service.md`. | doc reads true | deployment-modes | open |

### Identity and the gateway

| item | what | proof | plan | status |
|---|---|---|---|---|
| Workload agent (#25) | The workload socket, attestation and SVID issue of identity-contracts.md. | the contracts' tests, go-spiffe interop | both | shipped in v0.18.0 |
| Federated bundle (#33) | Sandboxes call EXPLICIT gateway endpoints (real TLS names, clients pointed at them); there is no transparent interception and no forwarder. A box authenticates with its X.509-SVID (mTLS) or a JWT-SVID whose audience is the gateway's SPIFFE ID. hush's part is identity and bundle only: `GET /v1/bundle` serves a federated bundle with every troupe machine's jwt-svid key, `spiffe_sequence` monotonic and persisted across restarts, so a gateway can verify another machine's SVID. hush's verifier keeps refusing an SVID outside its issuer's `/node/<node>/`. | refused: an older bundle after restart, an SVID outside its issuer's subtree, a JWT-SVID for another audience | sandbox-identity | not started |
| Grant time limits (#27) | `authorizeCred` becomes one check: the caller's identity token verified (chain, expiry, machine) plus the time limit of the (service, caller) grant held in hush. Admin revoke ends a time limit at once. The file-based consent of #11 and #14 is removed in the same change. | refused: no token, bad chain, expired token, another machine's subject, time limit passed or not yet started, revoked | both | not started; both plans list it, agree the claim on the issue |
| Serve the gateway (#35) | The gateway is one principal on hush's socket. Per call, (service, caller token): hush verifies the token, checks the time limit, and returns the real secret from the local replica or the root. Contract: `200` token + `expires_at`, `401 unattested`, `403 not_granted`, `503 credential_stale`, `502 transient`. | refused: any other principal, an invalid or expired caller token, a passed time limit, a service not in this replica | sandbox-identity | not started |
| Replicas (#36) | The root hush pushes each gateway machine the access tokens it may use, encrypted to that machine's key; read-only; re-pushed on refresh; a revoke removes the row at the next push. Refresh tokens stay on the root. | a machine gets only its rows; another machine's key cannot decrypt; a write to a replica is refused | sandbox-identity | not started |
| Federation (#28) | figaro federation: an upstream hush serves the machines' hushes over mTLS under the troupe CA (`services.hush.upstream`, `serveNodes`; troupe root on offline media). | another machine's cert, an expired cert, a subject from another machine refused | deployment-modes | not started |
| SSH user certificates (#29) | The git server trusts hush's OpenSSH user certificates (identity-contracts.md section 2), with a short principal per identity. | expired cert, other CA, principal not granted, static key after migration refused | sandbox-identity | not started |
| Per-aria identity (#30) | An aria's identity becomes unforgeable inside a shared sandbox once each aria runs under its own uid. | aria A's uid cannot get aria B's SVID | sandbox-identity | waits on figaro |

### Out of hush

- SSH host certificates and web, service and box TLS: step-ca. Draft #9 (an SSH host CA in hush) closes; its negative tests become step-ca acceptance tests.
- Static machine secrets: sops-nix.
- Model routing (providers, failover, quotas): the gateway's own concern. hush serves it credentials, `/status` and forced refresh.

## Decisions and open questions

**(a) CA split: DECIDED.** Workload identities are hush's SVIDs under the troupe CA (identity-contracts.md), which also signs figaro federation. step-ca signs SSH host certificates and web, service and box TLS. Neither blocks the other; the goal is to merge them into one system later.

**(b) Canonical repository: OPEN.** #8, #10 to #14 and v0.18.0 landed here on GitHub. A second, self-hosted copy of hush is still at v0.17.0 (2bdde24). Decide which one is canonical and mirror the other from it.
