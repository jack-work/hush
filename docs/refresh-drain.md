# Generic OAuth refresh drain

This change is a fake-tested local lifecycle barrier. It does not inspect, classify, repair or authorize reuse of the preserved native proof credential chain. No live login, refresh, restart or credential copy belongs to this branch.

## Failure in the earlier lifecycle

The earlier Manager.Stop cancelled its context, cleared cached token pointers and returned without joining refresh operations or proactive loops. An already admitted operation could subsequently persist a rotated pair, publish into the cleared cache, or write a relogin mark. Register, startup scrubbing, adoption and deletion also lacked a closed admission gate.

The credential service launched HTTP Shutdown on a goroutine, but Serve returns when its listener closes, before Shutdown necessarily finishes its active handlers. The command could reach its deferred manager stop and ownership unlock without proving either refresh or HTTP work had ended. The state lock's defer order was suitable; the stop operation was not a drain barrier.

## New local contract

Admission and positive WaitGroup registration occur together under one lifecycle mutex. Stop closes that gate before cancellation, joins admitted operations and proactive loops, then clears caches and returns. New work is never added once the gate closes. Concurrent or repeated Stop calls share one completion channel and the same stored outcome.

An admitted refresh that fully decodes and validates a successful response still syncs its temporary file, renames it, syncs the directory and only then publishes the new tuple. A concurrently cancelled context does not discard that complete successor. Stop cannot return until that commit or failure is resolved. Persistence failures never publish the successor and make the shutdown outcome uncertain. All three durable commit stages have independent fake failure tests.

Lost, partial or failed responses during shutdown return the distinct stopped API error. They do not try the previous refresh token, perform a second mint, or manufacture a permanent/relogin latch. They make the drain outcome uncertain because cancellation cannot prove what the provider did. An intentionally rejected account-mismatched successor also retains uncertainty rather than claiming a clean recoverable pair.

Start, Register, Adopt, Delete, Refresh, cached reads and metadata operations participate in the lifecycle. The proactive loop is registered before it is launched, and cancelled loops finish before Stop returns. The timer and filesystem primitives are private dependencies used by deterministic barrier/fault tests, not runtime configuration or an external testing endpoint.

## Explicit API and caller changes

- `Manager.Stop() error` now joins and returns nil or the fixed `ErrDrainUncertain`. That outcome is stable across concurrent and repeated calls. Nil describes a locally completed drain with no detected unresolved rotation/commit; it is never provider acceptance, a capacity assertion or permission to reuse an older unknown chain.
- `ErrStopped` is distinct from refresh-permanent and refresh-transient errors. Post-stop APIs return it rather than a token or a relogin instruction.
- `Manager.List()` now returns `(names, error)` so a stopped manager cannot masquerade as a successful empty credential list. The generic agent's OAuth list handler propagates the stopped code.
- `Manager.SetHTTPClient()` now returns an error and refuses mutation after stop. Client snapshots used by a mint are synchronized with that setup method. Constructor-local production setup occurs before the manager is published or started.
- Generic agent RPCs expose distinct `oauth_stopped` and `oauth_drain_uncertain` codes. Client sentinels do not classify either as permanent or transient. This change adds no provider retry, paid fallback or automatic login behavior.
- `Agent.Run` checks its shutdown result. `Agent.shutdown` waits for manager drain before zeroing the identity and releasing its process lock, logs a fixed unresolved-state message when needed and returns the error. An RPC shutdown reply is still only an acknowledgement of the request, not a custody receipt.
- `credserve.Login.Run` checks Stop before printing successful sign-in and checks it again through its defer. It never reports successful custody while a commit is unresolved.
- `runCredServe` uses `Server.ServeContext` and checks the stable manager result before its earlier-deferred ownership lock closes. A backup deferred check covers startup errors too.
- `Server.ServeContext` closes HTTP admission, drains the manager and waits for HTTP connection workers. A bounded HTTP Shutdown timeout closes remaining connections, then the connection-state barrier still joins their handlers. Manager persistence is not abandoned on that HTTP timeout. The owner lock remains held through both barriers.
- Test cleanup method values adapt to the error-returning Stop signature. Deliberately uncertain fake cases assert the result explicitly rather than treating cleanup as a clean-custody claim.

The generic agent is changed only for the drain error contract and propagation. Existing listener-publication races are not fixed or silently reclassified here.

## Fake evidence

The manager tests distinguish a valid success returned after cancellation from a lost/partial response. They cover directory-sync blocking, file-sync/rename/directory-sync failures, stable concurrent Stop outcomes, post-gate admission refusal, coalesced waiters, startup rewrite/adoption/registration/deletion barriers and proactive-loop joining.

A child process runs the same ServeContext used by the credential CLI with a real private-state flock. A valid fake response stays blocked after cancellation; a second owner cannot acquire the lock. After the manager completes, a still-active HTTP connection also keeps the owner lock busy. Only after both drains complete does the process release it. A fake persistence failure produces a fixed nonzero uncertain result rather than a successful custody receipt.

A separate real-TLS fake provider accepts a rotation and withholds its response while the test process crashes. The old durable pair remains, with no invented successor or relogin mark. That is an explicit unrecoverability/uncertainty gap, not a success test. The earlier fake crash-after-persist test remains the positive control for a fully committed successor.

No real token values or held credential files enter these tests or their logs.

## Recovery conditions and persistent lifecycle plan

A pair that was never spent, a fully received and durably committed successor, a provider-accepted rotation whose response was lost, and a failed/interrupted persistence attempt are different conditions. The preserved chain has not been inspected, so this change assigns it none of those conditions. Exit code zero from the earlier process does not classify it.

A future separately reviewed persistent owner must not inherit the API tool's hard lifetime. The proposed proof-only user service has Restart=no, no RuntimeMaxSec, TimeoutStopSec=infinity and SendSIGKILL=no. The controller may wait a bounded interval, but timeout means pending/held uncertainty, not a clean receipt, a kill escalation or permission to start another owner. Filesystem sync has no finite universal completion bound. The process lock remains held while local drain is still pending.

Source acceptance, passing fake tests or a locally clean drain do not authorize installation, startup, copying, fresh login or reuse of the preserved chain. Any recovery action requires a separate custody verdict and explicit King authority.
