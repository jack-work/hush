# hush as a system service

`services.hush` (flake output `nixosModules.hush`) runs the plan-credential
minter as system user `hush` (uid and gid 476), with its state in
`/var/lib/hush` (0700 hush) and three kinds of socket under `/run/hush`.

| socket | unit | who connects | what it answers |
|---|---|---|---|
| `/run/hush/cred.sock` | `hush-cred.socket` | `credUsers` (default `[ "figaro" ]`) | `GET /cred/<name>` for every instance: a short-lived bearer and its expiry. Nothing else. |
| `/run/hush/drop.sock` | `hush-drop.socket` | `dropUsers` (default none, and then no socket) | `POST /login-start/<name>`, `POST /login-complete/<name>` (ChatGPT, Copilot and Anthropic instances), `POST /refresh/<name>`. Replies carry status, a sign-in URL or a device code, never a token. |
| `/run/hush/admin.sock` | `hush-admin.socket` | the `hush` uid; root reaches it with `runuser -u hush` | `GET /status`, `POST /refresh/<name>`, the sign-in routes, `GET /cred/<name>` |
| `/run/hush/<principal>.sock` | `hush-<principal>.socket` | that principal's `users` | `GET /cred/<name>` for its granted instances |
| `/run/hush/systemd.sock` | `hush-loadcredential.socket` | systemd itself (peer uid 0), for units in `unitGrants` (default none, and then no socket) | raw bytes, no HTTP: the token for `LoadCredential=<id>:/run/hush/systemd.sock`, or nothing |

Each socket is 0600 `hush:hush` plus one `u:<user>:rw` ACL entry per listed
user, and the server checks the peer's `SO_PEERCRED` uid again. Group
membership grants nothing: a group gate fails for a process whose user manager
started before the user joined the group. The principal names `cred`, `drop`,
`admin` and `loadcredential` are taken.

## A unit's token by LoadCredential

A unit that needs a token and should hold no socket access of its own gets it
from systemd:

```nix
services.hush.unitGrants."keel-lieutenant.service".token = "ghe-read";
systemd.services.keel-lieutenant.serviceConfig.LoadCredential = [ "token:/run/hush/systemd.sock" ];
```

systemd connects from the abstract address `\0<random>/unit/<unit>/<id>`;
hush believes that unit name only from uid 0 (any process can bind an abstract
address), looks up `unitGrants.<unit>.<id>` and writes the raw token, which
the unit reads from `$CREDENTIALS_DIRECTORY/token`. Anything else is closed
having written nothing, and systemd still starts the unit, with an EMPTY
credential file: treat an empty credential as a failure. A token is read at
unit start, so a long-running unit restarts to get a fresh one.

One `hush.service` takes every socket by name. `hush-fence.service` loads the
egress fence (nftables table `inet hush`); `/var/lib/hush` is left out of every
restic backup.

## figaro on a house host

figaro needs nothing new. Each provider that takes a plan credential points its
existing `[cred]` table at the cred socket, and `figaro` stays in `credUsers`:

```toml
[cred]
socket = "/run/hush/cred.sock"
name   = "anthropic-work"
```

## Signing in

- ChatGPT, Copilot and Anthropic, from a person in `dropUsers`, with the
  minter running:

  ```sh
  curl -s --unix-socket /run/hush/drop.sock -X POST -d '{}' http://hush/login-start/chatgpt-personal
  # open authorize_url, then hand back the code with the handle
  curl -s --unix-socket /run/hush/drop.sock -X POST \
    -d '{"handle":"<handle>","code":"<code>"}' http://hush/login-complete/chatgpt-personal
  ```

  For an Anthropic instance the code is the `code#state` Anthropic shows after
  sign-in; a foreign or malformed paste answers 400 and spends nothing.

- Anthropic at the host's terminal still works, with the minter stopped (the
  state lock refuses a second owner):

  ```sh
  sudo systemctl stop hush-cred.socket hush-drop.socket hush-admin.socket hush.service
  sudo runuser -u hush -- hush-cred login anthropic-max
  sudo systemctl start hush-cred.socket hush-drop.socket hush-admin.socket
  ```

  Stop every `hush-<principal>.socket` too, or one connection restarts the
  minter mid-login.

- Status: `sudo runuser -u hush -- curl -s --unix-socket /run/hush/admin.sock http://hush/status`.

## The old name, `services.hush-cred`

`services.hush-cred` (and `nixosModules.hush-cred`) stays for one release and
renders exactly what it rendered before: user `hush-cred`, `/var/lib/hush-cred`,
`/run/hush-cred/cred.sock` (0660, group `socketGroup`) for `allowUser`, and the
units `hush-cred.service`, `hush-cred.socket`, `hush-cred-<principal>.socket`,
`hush-cred-fence.service`. It warns at evaluation. Bumping hush on a host that
uses it changes nothing on that host. Enabling both names is refused: they are
one minter on one uid.

## Moving a host from `services.hush-cred` to `services.hush`

The login state is moved, never copied: two minters holding the same refresh
token race to rotate it, and the loser's copy is dead. The old minter is
stopped before the state moves. Do it in a daytime window; on spain it is
folded into El Mayor's charter-consumer branch. The VM test `cred-rename-vm`
runs these steps.

What changes for the host:

| before | after |
|---|---|
| user and group `hush-cred` (476) | user and group `hush` (476): the files keep their owner by number |
| `/var/lib/hush-cred` | `/var/lib/hush` |
| `/run/hush-cred/cred.sock`, everything for `allowUser` | `/run/hush/cred.sock`, `GET /cred/<name>` for `credUsers`; status moved to the admin socket, refresh and sign-in to the drop box (refresh also on admin) |
| `/etc/hush-cred/config.toml` | `/etc/hush/config.toml` |
| `hush-cred.service`, `hush-cred-fence.service`, table `inet hush_cred` | `hush.service`, `hush-fence.service`, table `inet hush` |
| `allowUser`, `socketGroup` | `credUsers` (a list), `dropUsers`; the `socketGroup` group is no longer declared by hush |

Before moving a host, check what it runs today:

- A minter holding state with `grant = "anthropic"` (an `anthropic-max`
  instance) keeps `kind = "anthropic"`, the pinned Max sign-in. An instance
  that names its own client and token URL is `kind = "refresh_token"`.
- A host on a predecessor with a dynamic uid (spain's `hush-chatgpt`, state in
  `/var/lib/hush-chatgpt-spain-v1`) is not covered by the steps below: stop its
  socket and service, move its state to `/var/lib/hush`, `chown -R 476:476
  /var/lib/hush` (the server refuses state it does not own), and point
  `identityFile` at the moved identity. The VM test covers only the move from
  `services.hush-cred`.

Before the window, in the host's config branch:

1. Replace `services.hush-cred = { ... allowUser = "rou2"; socketGroup = "rou2"; ... }`
   with `services.hush = { ... credUsers = [ "rou2" ]; dropUsers = [ "rou2" <people> ]; ... }`.
   Keep `uid`, `recipient`, `identityFile`, `instances` and `egress` as they
   are. If `identityFile` lies under `/var/lib/hush-cred`, point it at the
   same file under `/var/lib/hush`.
2. Every consumer of `config.services.hush-cred.socketPath` now reads
   `config.services.hush.socketPath` (`/run/hush/cred.sock`). A consumer that
   called `/status`, `/refresh/<name>` or the sign-in routes on the old socket
   moves to the admin socket or the drop box. figaro's providers call only
   `GET /cred/<name>` and move as they are. rou2 does not: it posts
   `/refresh/<name>` on its minter socket to re-mint after an upstream 401,
   and `rou2 refresh` and `rou2 login` post `/refresh` and the sign-in routes
   there. On `/run/hush/cred.sock` those answer 404, so a 401 re-mint
   silently returns the cached bearer. Put rou2 in `dropUsers` as well as
   `credUsers`, and set rou2's `minter_socket = /run/hush/cred.sock` and
   `minter_control_socket = /run/hush/drop.sock`. A host whose rou2 lacks
   `minter_control_socket` stays on `services.hush-cred` until it has it.
3. Declare the old `socketGroup` group elsewhere if anything still uses it.

4. Build the system and keep its store path; do not switch yet.

In the window, on the host:

```sh
set -e
# 1. Stop the old minter, every socket that could start it again, then check nothing of it runs.
sudo systemctl stop 'hush-cred-*.socket' hush-cred.socket hush-cred.service
! pgrep -u hush-cred
# 2. Move the state: one rename on one file system, nothing left behind to copy from.
sudo test ! -e /var/lib/hush
sudo mv /var/lib/hush-cred /var/lib/hush
# 3. Switch to the system built before the window.
sudo /nix/store/<system>/bin/switch-to-configuration switch
# 4. Check: the same uid, the state where the new minter reads it, a token without a new sign-in.
test "$(id -u hush)" = 476
sudo runuser -u hush -- curl -s --unix-socket /run/hush/admin.sock http://hush/status
sudo runuser -u rou2 -- curl -s --unix-socket /run/hush/cred.sock http://hush/cred/anthropic-max | jq -r .expires_at
```

The old socket node stays in `/run/hush-cred` until reboot, answering nothing;
`sudo rm -r /run/hush-cred` tidies it. `/status` must show each instance `ok`, as before the window. An instance that
reads `unminted` means the state did not move: stop `hush.service` and look
before anyone signs in again, since a fresh sign-in strands the moved token.

Rollback, before any new sign-in: stop `hush.service` and every `hush-*.socket`,
`mv /var/lib/hush /var/lib/hush-cred`, switch back to the previous system. The
file format is the same under both names.
