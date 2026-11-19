{ pkgs, self }:
let
  hush = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/hush";
  pki = pkgs.runCommand "hush-workload-test-pki" { } ''
    mkdir $out
    cd $out
    ${hush} ca keygen root.key > /dev/null
    ${hush} ca root kelliher < root.key > root.pem
    ${hush} ca keygen inter.key > inter.pub
    ${hush} ca intermediate kelliher spain --public-key inter.pub < root.key > inter.pem
    ${hush} ca keygen merlin.key > merlin.pub
    ${hush} ca intermediate kelliher merlin --public-key merlin.pub < root.key > merlin.pem
    ${hush} ca keygen --jwt jwt.key > /dev/null
  '';
in
pkgs.testers.runNixOSTest {
  name = "hush-workload";

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
    };
    users.users.jack = { isNormalUser = true; uid = 1000; };
    environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default pkgs.openssl ];
    systemd.services.demo = {
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        StateDirectory = "demo";
        ExecStart = "${hush} workload x509 --trust-domain kelliher /var/lib/demo/svid";
      };
    };
  };

  testScript = ''
    spain.wait_for_unit("sockets.target")
    spain.succeed("test \"$(stat -c %a /run/hush/workload.sock)\" = 666")

    with subtest("(i) a system unit gets its unit identity"):
        spain.succeed("systemctl start demo.service")
        spain.succeed("openssl x509 -in /var/lib/demo/svid/svid.pem -noout -ext subjectAltName | grep -F 'URI:spiffe://kelliher/node/spain/unit/demo.service'")

    with subtest("(ii) a user inside a root unit (su from the test backdoor) gets its uid identity, not the unit's, and a JWT-SVID"):
        out = spain.succeed("su - jack -c '${hush} workload x509 --trust-domain kelliher /tmp/svid'")
        assert "spiffe://kelliher/node/spain/uid/1000" in out, out
        spain.succeed("su - jack -c '${hush} workload jwt --trust-domain kelliher spain' | grep -E '^ey'")

    with subtest("(iii) the issuer runs with no network, no capabilities, its own uid"):
        pid = spain.succeed("systemctl show -p MainPID --value hush-workload").strip()
        assert pid != "0", "hush-workload is not running"
        spain.succeed(f"test \"$(stat -c %U /proc/{pid})\" != root")
        spain.succeed(f"grep -E '^CapEff:\\s+0+$' /proc/{pid}/status")
        spain.succeed(f"test \"$(readlink /proc/{pid}/ns/net)\" != \"$(readlink /proc/1/ns/net)\"")

    with subtest("(iv) the intermediate key is not readable by workloads"):
        spain.fail("su - jack -c 'cat /etc/hush-test/inter.key'")

    with subtest("(v) an intermediate for another node is refused at start"):
        spain.succeed("cp ${pki}/merlin.key /etc/hush-test/merlin.key")
        out = spain.fail("${hush} workload serve --trust-domain kelliher --node spain --root-cert ${pki}/root.pem --intermediate-cert ${pki}/merlin.pem --intermediate-key /etc/hush-test/merlin.key --socket /tmp/x.sock 2>&1")
        assert "merlin" in out, out
  '';
}
