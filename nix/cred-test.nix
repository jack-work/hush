{ pkgs, self }:
let
  common = import ./cred-test-common.nix { inherit pkgs; };
  inherit (common) recipient forbiddenIP ptyLogin;
in
pkgs.testers.runNixOSTest {
  name = "hush";

  nodes.endpoint = common.endpoint;

  nodes.minter = { nodes, ... }: {
    imports = [ self.nixosModules.hush common.minterBase ];
    users.users.figaro = { isSystemUser = true; group = "figaro"; };
    users.groups.figaro = { };
    users.users.jack = { isNormalUser = true; };
    users.users.intruder = { isSystemUser = true; group = "intruder"; extraGroups = [ "figaro" "hush" ]; };
    users.groups.intruder = { };
    users.users.outsider = { isSystemUser = true; group = "outsider"; };
    users.groups.outsider = { };

    # credUsers is left at its default, [ "figaro" ].
    services.hush = {
      enable = true;
      dropUsers = [ "jack" ];
      inherit recipient;
      identityFile = "/etc/hush-cred-test/identity";
      instances.anthropic-work = {
        kind = "anthropic";
        clientId = "test-client";
        authorizeUrl = "https://claude.test/oauth/authorize";
        tokenUrl = "https://tokens.test/v1/oauth/token";
        redirectUri = "https://tokens.test/oauth/code/callback";
        scopes = "user:inference";
        audit = true;
      };
      instances.chatgpt-personal.kind = "chatgpt";
      # A principal with its own socket: outsider may read anthropic-work there and nothing else.
      principals.keel = { users = [ "outsider" ]; credentials = [ "anthropic-work" ]; };
    };

    systemd.services.local-http = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server --bind 127.0.0.1 8080 --directory /etc";
    };

    environment.etc."restic-pw".text = "test";
    services.restic.backups.vmtest = {
      repository = "/srv/restic";
      passwordFile = "/etc/restic-pw";
      paths = [ "/var/lib" ];
      initialize = true;
      timerConfig = null;
    };
    systemd.tmpfiles.rules = [ "f /var/lib/backup-control/present 0644 root root - here" ];
  };

  testScript = { nodes, ... }: ''
    import json, time

    CANARY = "rt-canary-vm"
    replies = []

    def cred(user, expect_status=None):
        out = minter.succeed(
            f"runuser -u {user} -- curl -s -w '\\n%{{http_code}}' --unix-socket /run/hush/cred.sock http://m/cred/anthropic-work"
        )
        body, status = out.rsplit("\n", 1)
        replies.append(body)
        if expect_status is not None:
            assert int(status) == expect_status, f"{user}: {status} {body}"
        return int(status), json.loads(body)

    def fake(key, value):
        endpoint.succeed(f"echo {value} > /run/fake/{key}")

    def count(name):
        return int(endpoint.succeed(f"cat /run/fake/{name} 2>/dev/null || echo 0").strip())

    start_all()
    endpoint.wait_for_unit("fake-endpoint.service")
    endpoint.wait_for_unit("dnsmasq.service")
    endpoint.wait_for_open_port(443)
    for u in ["hush-fence.service", "dnsmasq.service", "hush-cred.socket", "hush-drop.socket", "hush-admin.socket", "hush-keel.socket", "hush.service", "local-http.service"]:
        minter.wait_for_unit(u)
    minter.wait_for_open_port(8080)

    with subtest("sockets: 0600 hush, each opened to its users by a uid ACL only"):
        for sock, user in [("cred", "figaro"), ("drop", "jack"), ("admin", None)]:
            path = f"/run/hush/{sock}.sock"
            minter.succeed(f"test \"$(stat -c '%U %G' {path})\" = 'hush hush'")
            acl = minter.succeed(f"getfacl -p {path}").splitlines()
            for line in ["user::rw-", "group::---", "other::---"]:
                assert line in acl, (path, acl)
            named = [l for l in acl if l.startswith("user:") and not l.startswith("user::")]
            assert named == ([f"user:{user}:rw-"] if user else []), (path, acl)
        minter.succeed("test \"$(id -u hush)\" = 476")
        minter.fail("id hush-cred")

    with subtest("(iii) the egress fence: DNS and resolved token endpoints only"):
        minter.succeed("curl -sf --max-time 5 https://forbidden.test/")
        minter.succeed("curl -sf --max-time 5 http://127.0.0.1:8080/")
        minter.succeed("runuser -u hush -- curl -sf --max-time 5 https://tokens.test/")
        minter.fail("runuser -u hush -- curl -sf --max-time 5 https://forbidden.test/")
        minter.fail("runuser -u hush -- curl -sf --max-time 5 https://${forbiddenIP}/")
        minter.fail("runuser -u hush -- curl -sf --max-time 5 http://127.0.0.1:8080/")
        minter.succeed("nft list set inet hush allow4 | grep -q ${nodes.endpoint.networking.primaryIPAddress}")
        minter.fail("nft list set inet hush allow4 | grep -q ${forbiddenIP}")

    with subtest("before sign-in: sign-in needed"):
        status, doc = cred("figaro", 503)
        assert doc["reason"] == "sign-in needed", doc

    with subtest("(v) login refuses a piped code"):
        out = minter.fail("echo 'the-code#x' | runuser -u hush -- hush-cred login anthropic-work 2>&1")
        assert "not a terminal" in out, out
        assert count("logins") == 0

    with subtest("(v) login reads code#state from the terminal"):
        fake("login_expires_in", 35)
        # login refuses while `cred serve` owns the state (.credential-owner.lock): stop the owner first, as an operator would.
        minter.succeed("systemctl stop hush-cred.socket hush-drop.socket hush-admin.socket hush-keel.socket hush.service")
        print(minter.succeed("${pkgs.python3}/bin/python3 ${ptyLogin} hush"))
        minter.succeed("systemctl start hush-cred.socket hush-drop.socket hush-admin.socket hush-keel.socket")
        assert count("logins") == 1
        status, doc = cred("figaro", 200)
        assert doc["token"] == "at-login-1", doc

    with subtest("principal socket: 0600 hush plus a uid ACL, its grant only"):
        # 0600 plus one named-user entry: stat shows the ACL mask in the group bits, so read the ACL itself.
        minter.succeed("test \"$(stat -c '%U' /run/hush/keel.sock)\" = 'hush'")
        acl = minter.succeed("getfacl -p /run/hush/keel.sock")
        for line in ["user::rw-", "user:outsider:rw-", "group::---", "other::---"]:
            assert line in acl.splitlines(), acl
        out = minter.succeed("runuser -u outsider -- curl -s --unix-socket /run/hush/keel.sock http://m/cred/anthropic-work")
        replies.append(out)
        assert json.loads(out)["token"] == "at-login-1", out
        out = minter.succeed("runuser -u outsider -- curl -s -w '\n%{http_code}' --unix-socket /run/hush/keel.sock http://m/cred/not-granted")
        body, status = out.rsplit("\n", 1)
        assert status == "403" and json.loads(body)["error"] == "not_granted", out
        minter.fail("runuser -u figaro -- curl -sf --unix-socket /run/hush/keel.sock http://m/cred/anthropic-work")
        journal = minter.succeed("journalctl -u hush.service -o cat --no-pager")
        assert "cred: audit anthropic-work principal=keel" in journal, journal
        assert "at-login-1" not in journal, "a token reached the journal"

    def call(user, sock, method, path, body=None):
        data = f" -H 'Content-Type: application/json' -d '{body}'" if body is not None else ""
        out = minter.succeed(
            f"runuser -u {user} -- curl -s -X {method}{data} -w '\\n%{{http_code}}' --unix-socket /run/hush/{sock}.sock http://m{path}"
        )
        body, status = out.rsplit("\n", 1)
        replies.append(body)
        return int(status), json.loads(body)

    with subtest("cred socket: figaro's uid only; groups and other uids are refused"):
        status, doc = cred("figaro", 200)
        assert doc["token"] == "at-login-1", doc
        for user in ["intruder", "outsider", "jack"]:
            minter.fail(f"runuser -u {user} -- curl -s --unix-socket /run/hush/cred.sock http://m/cred/anthropic-work")
        # root passes the file mode; the SO_PEERCRED check in the server refuses it.
        status, doc = cred("root", 403)
        assert "token" not in doc, doc
        status, doc = call("figaro", "cred", "GET", "/status")
        assert status == 404 and "token" not in doc, doc
        status, doc = call("figaro", "cred", "POST", "/login-start/chatgpt-personal", "{}")
        assert status == 404, doc

    with subtest("drop box: a drop user signs in and refreshes, and can read nothing back"):
        status, doc = call("jack", "drop", "POST", "/login-start/chatgpt-personal", "{}")
        assert status == 200 and doc["status"] == "started", doc
        assert sorted(doc) == ["authorize_url", "handle", "status"], doc
        assert doc["authorize_url"].startswith("https://auth.openai.com/oauth/authorize?"), doc
        status, doc = call("jack", "drop", "POST", "/login-complete/chatgpt-personal", '{"handle":"not-the-handle","code":"c"}')
        assert status == 400 and doc["error"] == "invalid_session", doc
        for name in ["anthropic-work", "chatgpt-personal"]:
            status, doc = call("jack", "drop", "GET", f"/cred/{name}")
            assert status == 403 and doc["error"] == "not_granted" and "token" not in doc, doc
        status, doc = call("jack", "drop", "GET", "/status")
        assert status == 404, doc
        # The sign-in started above holds chatgpt-personal, so this reaches the refresh route without touching upstream.
        status, doc = call("jack", "drop", "POST", "/refresh/chatgpt-personal", "{}")
        assert status == 409 and doc["error"] == "operation_busy" and "token" not in doc, doc
        for user in ["figaro", "intruder", "outsider"]:
            minter.fail(f"runuser -u {user} -- curl -s --unix-socket /run/hush/drop.sock http://m/status")
        status, doc = call("root", "drop", "POST", "/login-start/chatgpt-personal", "{}")
        assert status == 403, doc

    with subtest("admin socket: the hush uid reads status; nobody else"):
        status, doc = call("hush", "admin", "GET", "/status")
        assert status == 200, doc
        # The 35 s sign-in token is inside the serve floor by now, and /status never refreshes: "failing" is the honest state.
        assert doc["anthropic-work"]["state"] in ("ok", "failing") and doc["anthropic-work"]["expires_at"] > 0, doc
        assert doc["chatgpt-personal"]["state"] == "unminted", doc
        assert "token" not in json.dumps(doc), doc
        for user in ["figaro", "jack", "intruder"]:
            minter.fail(f"runuser -u {user} -- curl -s --unix-socket /run/hush/admin.sock http://m/status")
        status, doc = call("root", "admin", "GET", "/status")
        assert status == 403, doc

    with subtest("(ii) N concurrent calls during a refresh cost one POST"):
        fake("mode", "slow")
        fake("expires_in", 45)
        time.sleep(6)
        minter.succeed(
            "for i in $(seq 20); do runuser -u figaro -- curl -s --unix-socket /run/hush/cred.sock "
            "http://m/cred/anthropic-work > /tmp/r$i & done; wait"
        )
        assert count("posts") == 1, count("posts")
        for i in range(1, 21):
            body = minter.succeed(f"cat /tmp/r{i}")
            replies.append(body)
            assert json.loads(body)["token"] == "at-1", body

    with subtest("(ii) repeated calls cannot storm the endpoint"):
        fake("mode", "ok")
        time.sleep(16)
        for _ in range(20):
            cred("figaro")
        assert count("posts") == 1, count("posts")

    with subtest("persist-before-use: killed between the POST and the write"):
        fake("mode", "hang")
        minter.succeed("systemctl restart hush.service")
        minter.succeed("setsid sh -c 'runuser -u figaro -- curl -s --max-time 30 --unix-socket /run/hush/cred.sock http://m/cred/anthropic-work > /tmp/killed 2>&1' >/dev/null 2>&1 < /dev/null &")
        endpoint.wait_until_succeeds("test $(cat /run/fake/posts) = 2")
        minter.succeed("systemctl kill -s KILL hush.service")
        fake("mode", "ok")
        fake("expires_in", 45)
        minter.succeed("systemctl restart hush.service")
        status, doc = cred("figaro", 200)
        assert doc["token"] == "at-3", doc
        last = endpoint.succeed("cat /run/fake/last_refresh").strip()
        assert last == "rt-canary-vm-7c1e9f3a2b-1", f"the next life refreshed with {last}, not the persisted token"
        assert "at-killed" not in minter.succeed("cat /tmp/killed")

    with subtest("(i) the token endpoint's echo of a refresh token stays inside"):
        time.sleep(16)
        fake("mode", "fail-echo")
        minter.succeed("systemctl restart hush.service")
        cred("figaro")
        assert count("posts") == 4, count("posts")
        fake("mode", "refuse-echo")
        minter.succeed("systemctl restart hush.service")
        status, doc = cred("figaro", 503)
        assert doc["reason"] == "sign-in needed", doc
        assert endpoint.succeed("cat /run/fake/last_refresh").startswith(CANARY), "the canary never reached the endpoint"
        journal = minter.succeed("journalctl -o cat --no-pager")
        assert CANARY not in journal, "a refresh token reached the journal"
        for body in replies:
            assert CANARY not in body, body
        minter.fail("grep -r rt-canary-vm /var/lib/hush")

    with subtest("(iv) the state directory is left out of backups"):
        minter.succeed("systemctl start restic-backups-vmtest.service")
        listing = minter.succeed("restic -r /srv/restic --password-file /etc/restic-pw ls latest")
        assert "/var/lib/backup-control/present" in listing, "CONTROL: the backup missed /var/lib"
        assert "/var/lib/hush" not in listing, "the minter's state was backed up"
  '';
}
