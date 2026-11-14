# ChatGPT credentials for rou2

The system credential minter can own a fresh ChatGPT OAuth session. This is separate from figaro's declared-provider OAuth work: the new capability here is a system minter instance with pinned ChatGPT endpoints and atomic account metadata publication. No extra rotating token owner is introduced on the figaro path.

Add a private instance to the existing credential configuration:

```toml
[instances.chatgpt-personal]
kind = "chatgpt"
```

The Nix module also accepts `services.hush-cred.instances.chatgpt-personal.kind = "chatgpt"`. Authorization, token exchange, public client and callback are fixed to the native Codex OAuth flow. Operator endpoint/client/callback overrides are rejected. The minter's egress fence permits `auth.openai.com:443`, not the inference backend. Rou2 separately pins inference to `https://chatgpt.com/backend-api/codex/responses`.

## Custody and publication

The existing OAuth Manager remains the only refresh mechanism. It serializes refreshes, encrypts access and refresh tokens at rest, syncs the rotated tuple and directory before publishing it, and keeps the old in-memory tuple if persistence fails. A process lock excludes another system minter or login against the same state directory. The state directory must be owned by that user and mode 0700. Login must run with the service stopped; first login and replacement use the same lock. The private lock file rejects symlinks, other owners and additional hard links.

The token owner reads the account and expiry from access-token claims received directly from the pinned token endpoint over TLS. These claims address the account; they are not an authorization grant. An ID token, when present, must agree on account identity. An invalid account identifier or account change during refresh refuses publication. Account identifiers match `^[A-Za-z0-9_-]{1,128}$`. Refresh tokens and ID tokens never appear on the minter socket. Endpoint response text never appears in ChatGPT errors or logs.

A successful peer-authorized `GET /cred/chatgpt-personal` returns:

```json
{"name":"chatgpt-personal","token":"access-bearer","expires_at":1234567890,"account_id":"account_1"}
```

All fields come from one immutable persisted credential tuple. The name field is unchanged from the existing protocol. `account_id` is optional for legacy credentials and mandatory for ChatGPT. The peer UID check and Unix socket permissions are unchanged. A stale or unusable login remains HTTP 503 with `reason: "sign-in needed"`.

Never copy the temporary subscription proxy's rotating credential chain into this service. Use a fresh browser login. Two active consumers of the same refresh chain can invalidate each other. This extension does not authorize importing or reading that chain.

## Human login after review

These commands are instructions for Gluck, not authorization for an agent to log in or change services. Do not run them until the credential delta and rou2 integration are accepted.

Stop the minter service and its activation socket, then run login as its state owner:

```sh
sudo systemctl stop hush-cred.service hush-cred.socket
sudo -u hush-cred hush cred login chatgpt-personal --config /etc/hush-cred/config.toml --state-dir /var/lib/hush-cred
```

The command binds `127.0.0.1:1455` before printing the authorization URL. Open that URL in a browser. The registered callback is exactly `http://localhost:1455/auth/callback`. State and the PKCE verifier are generated independently. Codes never go in argv or terminal output. A wrong state exchanges no code; cancellation closes the listener. A busy callback port refuses before login begins.

If login runs on spain and the browser is on gluck, Gluck must first establish a private local forward, with local port 1455 free:

```sh
ssh -N -L 127.0.0.1:1455:127.0.0.1:1455 spain
```

Keep that SSH session open until the browser callback completes. The temporary proxy may currently own port 1455; do not stop it or move its credentials without a separately approved cutover. A replacement login requires `--replace`, with the service still stopped. Start the service and socket after successful login:

```sh
sudo systemctl start hush-cred.socket hush-cred.service
```

## Safe refresh checkpoint

The same admitted peer can request refresh without receiving a bearer:

```sh
sudo -u rou2 curl --fail --silent --show-error --unix-socket /run/hush-cred/cred.sock -X POST http://minter/refresh/chatgpt-personal
```

Success returns only readiness and whether this request performed a refresh, for example `{"ready":true,"refreshed":true}`. A concurrent request or one inside the 30-second minimum refresh interval can return `refreshed:false`; it does not bypass the refresh floor. Refused refreshes return a fixed sign-in-needed error. No token, account metadata or provider response body is returned by this route. It uses the same Unix peer-credential gate; there is no TCP administration endpoint.

A fake endpoint can prove refresh serialization, persistence and restart behavior. A live browser login, live subscription refresh endurance and inference/tool replay through rou2 are separate acceptance steps. No live success is claimed by these tests. Subscription exhaustion must stop the commission, never use an API-key fallback.
