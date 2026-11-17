# Anthropic Max credentials for rou2

The system credential minter can own a fresh Claude Max sign-in. This is separate from figaro's own Anthropic login in the per-user hush agent: a minter instance is its own sign-in with its own refresh chain, never a copy of another.

Add a private instance to the credential configuration:

```toml
[instances.anthropic-max]
kind = "anthropic"
```

The Nix module accepts `services.hush-cred.instances.anthropic-max.kind = "anthropic"`. Every other field is filled in and pinned, and an override is refused when the config loads:

| field | value |
|---|---|
| authorize_url | `https://claude.ai/oauth/authorize` |
| token_url | `https://console.anthropic.com/v1/oauth/token` |
| redirect_uri | `https://console.anthropic.com/oauth/code/callback` |
| client_id | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` (the Claude Code public client) |
| scopes | `user:profile user:inference` |

These are the values figaro's own Anthropic login uses (`internal/auth/anthropic.go`). The egress fence opens `console.anthropic.com:443` only; the authorize host is visited by the browser, never by the minter. A policy change on Anthropic's side is a source change here, not a config edit.

The generic config-driven refresh-token kind that used to be called `anthropic` is now `refresh_token`. A config that gave kind `anthropic` its own URLs no longer loads. Nothing was deployed with one.

## Custody

The existing OAuth Manager remains the only refresh mechanism. It serializes refreshes, persists and syncs each rotated pair before publishing it, and encrypts both tokens at rest. The refresh is the form-encoded `refresh_token` grant; a 429 or 5xx from the token endpoint is transient, any other refusal marks the credential sign-in needed. Endpoint response text, refresh tokens and authorization codes never appear in a reply, a log or an error. Redirects are not followed.

A credential file written under any config other than the pinned one is not served and its refresh token is never spent: the reply is 503 `sign-in needed`.

`GET /cred/anthropic-max` returns `{"name","token","expires_at"}`, as before. The peer UID gate is unchanged.

## Sign-in

Two ways, both a fresh browser login by the account owner. Neither is for an agent to run.

Remote, from rou2 (the route the `rou2 login` command uses): `POST /login-start/<name>` returns `{"status":"started","authorize_url","handle"}`. The URL carries an S256 challenge and a state independent of the verifier and the handle. The human opens it, signs in, and pastes the `code#state` Anthropic shows. `POST /login-complete/<name>` with `{"handle","code"}` checks the pasted state against this login's before any code is spent, exchanges it, and stores the pair through the persist path. A foreign or malformed paste answers 400 and spends nothing; the pending login stays open for its five minutes. A refused code leaves the live chain as it was. The handle works once.

Local, on the host as the minter's uid: `sudo -u hush-cred hush cred login anthropic-max`, with the service stopped, pasting `code#state` at the hidden prompt. `--replace` signs over a live credential.

Never copy figaro's Anthropic chain into this service, and never run `claude` or figaro against the same grant: two consumers of one refresh chain strand it.

## Refresh checkpoint

`POST /refresh/anthropic-max` answers `{"ready":true,"refreshed":true}` and nothing else, on the same peer gate.

## What is proved

Fake token endpoints, reached through the pinned URL by a rewriting transport, prove the pins, the rotation chain, the persist path, the sign-in refusals and the absence of tokens from replies, logs and disk. A live sign-in and a live refresh are separate operator checks. In particular nothing here has yet shown that Anthropic accepts a state different from the PKCE verifier on the code exchange, which figaro's own login does not exercise.
