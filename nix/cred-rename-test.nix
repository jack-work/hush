{ pkgs, self }:
let
  common = import ./cred-test-common.nix { inherit pkgs; };
  inherit (common) recipient ptyLogin;
  minter = {
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
in
pkgs.testers.runNixOSTest {
  name = "hush-rename";

  nodes.endpoint = common.endpoint;

  # Boots under the old name, as spain and the charter run it today; the renamed specialisation is the target of
  # the runbook in docs/hush-system-service.md.
  nodes.minter = { lib, ... }: {
    imports = [ self.nixosModules.hush-cred common.minterBase ];
    users.users.rou2 = { isSystemUser = true; group = "rou2"; };
    users.groups.rou2 = { };
    services.hush-cred = minter // { enable = true; };

    specialisation.renamed.configuration = {
      services.hush-cred.enable = lib.mkForce false;
      services.hush = minter // { enable = true; credUsers = [ "rou2" ]; };
    };
  };

  testScript = ''
    import json

    def token(sock):
        out = minter.succeed(f"runuser -u rou2 -- curl -s --unix-socket {sock} http://m/cred/anthropic-work")
        return json.loads(out)

    def count(name):
        return int(endpoint.succeed(f"cat /run/fake/{name} 2>/dev/null || echo 0").strip())

    start_all()
    endpoint.wait_for_unit("fake-endpoint.service")
    endpoint.wait_for_open_port(443)

    with subtest("the old name boots as before"):
        for u in ["hush-cred-fence.service", "hush-cred.socket", "hush-cred.service"]:
            minter.wait_for_unit(u)
        minter.succeed("test \"$(stat -c '%U %G %a' /run/hush-cred/cred.sock)\" = 'hush-cred rou2 660'")
        minter.succeed("test \"$(id -u hush-cred)\" = 476")
        minter.succeed("nft list table inet hush_cred")
        assert token("/run/hush-cred/cred.sock")["reason"] == "sign-in needed"

    with subtest("sign in under the old name"):
        minter.succeed("systemctl stop hush-cred.socket hush-cred.service")
        print(minter.succeed("${pkgs.python3}/bin/python3 ${ptyLogin} hush-cred"))
        minter.succeed("systemctl start hush-cred.socket")
        assert token("/run/hush-cred/cred.sock")["token"] == "at-login-1"
        assert count("logins") == 1

    with subtest("the runbook: stop the old minter, move its state, switch"):
        minter.succeed("systemctl stop hush-cred.socket hush-cred.service")
        minter.succeed("test -z \"$(pgrep -u hush-cred)\"")
        minter.succeed("mv /var/lib/hush-cred /var/lib/hush")
        minter.succeed("/run/current-system/specialisation/renamed/bin/switch-to-configuration test")
        for u in ["hush-fence.service", "hush-cred.socket", "hush-admin.socket", "hush.service"]:
            minter.wait_for_unit(u)

    with subtest("renamed: same uid, state moved not copied, no new sign-in"):
        minter.succeed("test \"$(id -u hush)\" = 476")
        minter.fail("id hush-cred")
        minter.fail("test -e /var/lib/hush-cred")
        minter.succeed("test \"$(stat -c '%U %a' /var/lib/hush)\" = 'hush 700'")
        minter.fail("nft list table inet hush_cred")
        minter.succeed("nft list table inet hush")
        # systemd leaves a stopped socket's node behind; nothing answers on it.
        minter.fail("runuser -u rou2 -- curl -s --unix-socket /run/hush-cred/cred.sock http://m/cred/anthropic-work")
        assert token("/run/hush/cred.sock")["token"] == "at-login-1"
        assert count("logins") == 1, count("logins")
        assert count("posts") == 0, count("posts")
        status = json.loads(minter.succeed("runuser -u hush -- curl -s --unix-socket /run/hush/admin.sock http://m/status"))
        assert status["anthropic-work"]["state"] == "ok", status
  '';
}
