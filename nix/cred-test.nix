{ pkgs, self }:
let
  recipient = "age1q420hq4mgxjlq2nw589e8hehfv3c6ld32z772qldwwlsvg89yqlqcgq8rd";
  forbiddenIP = "192.168.1.50";

  certs = pkgs.runCommand "hush-cred-test-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -subj /CN=test-ca -keyout ca.key -out $out/ca.pem
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj /CN=tokens.test -keyout $out/leaf.key -out leaf.csr
    printf 'subjectAltName=DNS:tokens.test,DNS:forbidden.test,IP:${forbiddenIP}\n' > ext
    openssl x509 -req -in leaf.csr -CA $out/ca.pem -CAkey ca.key -CAcreateserial \
      -days 3650 -extfile ext -out $out/leaf.pem
  '';

  ptyLogin = pkgs.writeText "pty-login.py" ''
    import os, pty, re, sys
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("runuser", ["runuser", "-u", "hush-cred", "--", "hush-cred", "login", "anthropic-work"])
    buf = b""
    while b"code#state: " not in buf:
        chunk = os.read(fd, 4096)
        if not chunk:
            sys.stdout.write(buf.decode(errors="replace"))
            sys.exit(2)
        buf += chunk
    state = re.search(rb"state=([A-Za-z0-9_-]+)", buf).group(1).decode()
    os.write(fd, f"the-code#{state}\n".encode())
    out = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    _, status = os.waitpid(pid, 0)
    sys.stdout.write((buf + out).decode(errors="replace"))
    sys.exit(os.waitstatus_to_exitcode(status))
  '';
in
pkgs.testers.runNixOSTest {
  name = "hush-cred";

  nodes.endpoint = { nodes, ... }: {
    networking.interfaces.eth1.ipv4.addresses = [{ address = forbiddenIP; prefixLength = 24; }];
    networking.firewall.allowedTCPPorts = [ 443 ];
    networking.firewall.allowedUDPPorts = [ 53 ];
    services.dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        no-resolv = true;
        address = [
          "/tokens.test/${nodes.endpoint.networking.primaryIPAddress}"
          "/forbidden.test/${forbiddenIP}"
        ];
      };
    };
    systemd.services.fake-endpoint = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${./cred-fake-endpoint.py} ${certs}/leaf.pem ${certs}/leaf.key";
    };
  };

  nodes.minter = { nodes, ... }: {
    imports = [ self.nixosModules.hush-cred ];
    security.pki.certificateFiles = [ "${certs}/ca.pem" ];
    environment.systemPackages = [ pkgs.curl pkgs.restic pkgs.nftables ];
    networking.nameservers = pkgs.lib.mkForce [ "127.0.0.1" ];
    services.dnsmasq = {
      enable = true;
      settings = {
        no-resolv = true;
        server = [ nodes.endpoint.networking.primaryIPAddress ];
        listen-address = [ "127.0.0.1" ];
        bind-interfaces = true;
      };
    };

    users.users.rou2 = { isSystemUser = true; group = "rou2"; };
    users.users.intruder = { isSystemUser = true; group = "intruder"; extraGroups = [ "rou2" ]; };
    users.groups.intruder = { };
    users.users.outsider = { isSystemUser = true; group = "outsider"; };
    users.groups.outsider = { };

    environment.etc."hush-cred-test/identity" = { source = ./cred-test-identity.txt; mode = "0400"; };

    services.hush-cred = {
      enable = true;
      inherit recipient;
      identityFile = "/etc/hush-cred-test/identity";
      instances.anthropic-work = {
        kind = "anthropic";
        clientId = "test-client";
        authorizeUrl = "https://claude.test/oauth/authorize";
        tokenUrl = "https://tokens.test/v1/oauth/token";
        redirectUri = "https://tokens.test/oauth/code/callback";
        scopes = "user:inference";
      };
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
            f"runuser -u {user} -- curl -s -w '\\n%{{http_code}}' --unix-socket /run/hush-cred/cred.sock http://m/cred/anthropic-work"
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
    for u in ["hush-cred-fence.service", "dnsmasq.service", "hush-cred.socket", "hush-cred.service", "local-http.service"]:
        minter.wait_for_unit(u)
    minter.wait_for_open_port(8080)

    with subtest("socket is the minter's, group rou2, 0660"):
        minter.succeed("test \"$(stat -c '%U %G %a' /run/hush-cred/cred.sock)\" = 'hush-cred rou2 660'")

    with subtest("(iii) the egress fence: DNS and resolved token endpoints only"):
        minter.succeed("curl -sf --max-time 5 https://forbidden.test/")
        minter.succeed("curl -sf --max-time 5 http://127.0.0.1:8080/")
        minter.succeed("runuser -u hush-cred -- curl -sf --max-time 5 https://tokens.test/")
        minter.fail("runuser -u hush-cred -- curl -sf --max-time 5 https://forbidden.test/")
        minter.fail("runuser -u hush-cred -- curl -sf --max-time 5 https://${forbiddenIP}/")
        minter.fail("runuser -u hush-cred -- curl -sf --max-time 5 http://127.0.0.1:8080/")
        minter.succeed("nft list set inet hush_cred allow4 | grep -q ${nodes.endpoint.networking.primaryIPAddress}")
        minter.fail("nft list set inet hush_cred allow4 | grep -q ${forbiddenIP}")

    with subtest("before sign-in: sign-in needed"):
        status, doc = cred("rou2", 503)
        assert doc["reason"] == "sign-in needed", doc

    with subtest("(v) login refuses a piped code"):
        out = minter.fail("echo 'the-code#x' | runuser -u hush-cred -- hush-cred login anthropic-work 2>&1")
        assert "not a terminal" in out, out
        assert count("logins") == 0

    with subtest("(v) login reads code#state from the terminal"):
        fake("login_expires_in", 35)
        print(minter.succeed("${pkgs.python3}/bin/python3 ${ptyLogin}"))
        assert count("logins") == 1
        status, doc = cred("rou2", 200)
        assert doc["token"] == "at-login-1", doc

    with subtest("peer credentials: a group member that is not rou2 is refused"):
        status, doc = cred("intruder", 403)
        assert "token" not in doc, doc
        minter.fail("runuser -u outsider -- curl -sf --unix-socket /run/hush-cred/cred.sock http://m/cred/anthropic-work")

    with subtest("(ii) N concurrent calls during a refresh cost one POST"):
        fake("mode", "slow")
        fake("expires_in", 45)
        time.sleep(6)
        minter.succeed(
            "for i in $(seq 20); do runuser -u rou2 -- curl -s --unix-socket /run/hush-cred/cred.sock "
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
            cred("rou2")
        assert count("posts") == 1, count("posts")

    with subtest("persist-before-use: killed between the POST and the write"):
        fake("mode", "hang")
        minter.succeed("systemctl restart hush-cred.service")
        minter.succeed("setsid sh -c 'runuser -u rou2 -- curl -s --max-time 30 --unix-socket /run/hush-cred/cred.sock http://m/cred/anthropic-work > /tmp/killed 2>&1' >/dev/null 2>&1 < /dev/null &")
        endpoint.wait_until_succeeds("test $(cat /run/fake/posts) = 2")
        minter.succeed("systemctl kill -s KILL hush-cred.service")
        fake("mode", "ok")
        fake("expires_in", 34)
        minter.succeed("systemctl restart hush-cred.service")
        status, doc = cred("rou2", 200)
        assert doc["token"] == "at-3", doc
        last = endpoint.succeed("cat /run/fake/last_refresh").strip()
        assert last == "rt-canary-vm-7c1e9f3a2b-1", f"the next life refreshed with {last}, not the persisted token"
        assert "at-killed" not in minter.succeed("cat /tmp/killed")

    with subtest("(i) the token endpoint's echo of a refresh token stays inside"):
        time.sleep(5)
        fake("mode", "fail-echo")
        minter.succeed("systemctl restart hush-cred.service")
        cred("rou2")
        assert count("posts") == 4, count("posts")
        fake("mode", "refuse-echo")
        minter.succeed("systemctl restart hush-cred.service")
        status, doc = cred("rou2", 503)
        assert doc["reason"] == "sign-in needed", doc
        assert endpoint.succeed("cat /run/fake/last_refresh").startswith(CANARY), "the canary never reached the endpoint"
        journal = minter.succeed("journalctl -o cat --no-pager")
        assert CANARY not in journal, "a refresh token reached the journal"
        for body in replies:
            assert CANARY not in body, body
        minter.fail("grep -r rt-canary-vm /var/lib/hush-cred")

    with subtest("(iv) the state directory is left out of backups"):
        minter.succeed("systemctl start restic-backups-vmtest.service")
        listing = minter.succeed("restic -r /srv/restic --password-file /etc/restic-pw ls latest")
        assert "/var/lib/backup-control/present" in listing, "CONTROL: the backup missed /var/lib"
        assert "/var/lib/hush-cred" not in listing, "the minter's state was backed up"
  '';
}
