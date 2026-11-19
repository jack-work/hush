{ pkgs, self }:
# Sandbox identities end to end: real systemd-nspawn machines in machine.slice, registered with machined, in fixed
# user-namespace ranges, asking the hardened workload socket over a bind mount. The unit tests pin each rule on
# fixtures; this checks the reads (machined over D-Bus, uid_map, the payload cgroup) inside the issuer's sandboxing.
let
  hush = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/hush";
  pki = pkgs.runCommand "hush-machine-test-pki" { } ''
    mkdir $out
    cd $out
    ${hush} ca keygen root.key > /dev/null
    ${hush} ca root kelliher < root.key > root.pem
    ${hush} ca keygen inter.key > inter.pub
    ${hush} ca intermediate kelliher spain --public-key inter.pub < root.key > inter.pem
    ${hush} ca keygen --jwt jwt.key > /dev/null
  '';
  base = 1895825408; # 0x71000000
  size = 65536;
  # Sandbox machines of one template, sbx@<instance>: nspawn keeps the unit (so the payload is under
  # machine.slice/sbx@<instance>.service/payload), registers with machined, maps root inside to a host range, and runs
  # one client as pid 2 that prints its JWT-SVID. Instances g1/g2 are A in its range k=1; g3 is A in range k=3 (a stale
  # or picked userns); g4 is A not registered with machined; spool-z is a machine outside the map.
  sbx = pkgs.writeShellScript "sbx" ''
    set -eu
    i=$1
    userns=${toString (base + size)}:${toString size}
    register=yes
    case $i in
      spool-a-g3) userns=${toString (base + 3 * size)}:${toString size} ;;
      spool-a-g4) register=no ;;
    esac
    mkdir -p /var/lib/sbx/$i/etc /var/lib/sbx/$i/run/hush /var/lib/sbx/$i/nix/store
    echo ID=sbx > /var/lib/sbx/$i/etc/os-release
    exec ${pkgs.systemd}/bin/systemd-nspawn --quiet --keep-unit --register=$register --machine=$i \
      --private-users=$userns --private-users-ownership=off --directory=/var/lib/sbx/$i --as-pid2 \
      --bind-ro=/nix/store --bind-ro=/run/hush/workload.sock \
      ${hush} workload jwt --trust-domain kelliher rou2
  '';
in
pkgs.testers.runNixOSTest {
  name = "hush-workload-machines";

  nodes.spain = { ... }: {
    imports = [ self.nixosModules.hush-workload ];
    environment.etc."hush-test/inter.key" = { source = "${pki}/inter.key"; mode = "0400"; };
    environment.etc."hush-test/jwt.key" = { source = "${pki}/jwt.key"; mode = "0400"; };
    services.hush-workload = {
      enable = true;
      trustDomain = "kelliher";
      node = "spain";
      rootCert = "${pki}/root.pem";
      intermediateCert = "${pki}/inter.pem";
      intermediateKey = "/etc/hush-test/inter.key";
      jwtKey = "/etc/hush-test/jwt.key";
      policy = "node+machines";
      sandboxes = {
        template = "sbx";
        inherit base size;
        machines."spool-a" = { id = "a"; k = 1; };
        machines."spool-b" = { id = "b"; k = 2; };
      };
    };
    virtualisation.memorySize = 1024;
    systemd.services."sbx@".serviceConfig = { Type = "oneshot"; Slice = "machine.slice"; ExecStart = "${sbx} %i"; };
  };

  testScript = ''
    import base64, json

    def subject(unit):
        out = spain.succeed(f"journalctl -u {unit} -o cat --no-pager")
        tokens = [l for l in out.split() if l.startswith("ey")]
        assert tokens, f"{unit} printed no token:\n{out}"
        claims = tokens[-1].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))["sub"]

    spain.wait_for_unit("sockets.target")

    with subtest("(i) the client in sandbox A's payload gets A's identity, generation stripped"):
        spain.succeed("systemctl start sbx@spool-a-g1.service")
        sub = subject("sbx@spool-a-g1.service")
        assert sub == "spiffe://kelliher/node/spain/unit/sbx.service/spool-a", sub

    with subtest("(ii) a rebuilt A (g2) gets the same identity"):
        spain.succeed("systemctl start sbx@spool-a-g2.service")
        sub = subject("sbx@spool-a-g2.service")
        assert sub == "spiffe://kelliher/node/spain/unit/sbx.service/spool-a", sub

    with subtest("(iii) a machine not in the map is refused"):
        spain.fail("systemctl start sbx@spool-z-g1.service")
        out = spain.succeed("journalctl -u hush-workload -o cat --no-pager")
        assert "sandbox spool-z-g1: not in the sandbox map" in out, out

    with subtest("(iv) A's name in another range (not k=1) is refused"):
        spain.fail("systemctl start sbx@spool-a-g3.service")
        out = spain.succeed("journalctl -u hush-workload -o cat --no-pager")
        assert "sandbox spool-a-g3: user namespace" in out and "is not range k=1" in out, out

    with subtest("(v) A unregistered with machined is refused"):
        spain.fail("systemctl start sbx@spool-a-g4.service")
        out = spain.succeed("journalctl -u hush-workload -o cat --no-pager")
        assert "sandbox spool-a-g4: not registered with machined" in out, out

    with subtest("(vi) a host unit keeps its unit identity under node+machines"):
        out = spain.succeed("systemd-run --wait --pipe -p DynamicUser=yes ${hush} workload jwt --trust-domain kelliher rou2")
        token = [l for l in out.split() if l.startswith("ey")][-1].split(".")[1]
        sub = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))["sub"]
        assert sub.startswith("spiffe://kelliher/node/spain/unit/run-"), sub
  '';
}
