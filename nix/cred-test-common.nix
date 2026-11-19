{ pkgs }:
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
        os.execvp("runuser", ["runuser", "-u", sys.argv[1], "--", "hush-cred", "login", "anthropic-work"] + sys.argv[2:])
    buf = b""
    while b"code#state: " not in buf:
        try:
            chunk = os.read(fd, 4096)
        except OSError:  # Linux: EIO once the child side closes; that is EOF
            chunk = b""
        if not chunk:
            _, st = os.waitpid(pid, 0)
            sys.stdout.write(buf.decode(errors="replace") + f"\n[login exited before the prompt: status {os.waitstatus_to_exitcode(st)}]\n")
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
{
  inherit recipient forbiddenIP certs ptyLogin;

  endpoint = { nodes, ... }: {
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

  minterBase = { nodes, ... }: {
    security.pki.certificateFiles = [ "${certs}/ca.pem" ];
    environment.systemPackages = [ pkgs.curl pkgs.restic pkgs.nftables pkgs.acl ];
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

    environment.etc."hush-cred-test/identity" = { source = ./cred-test-identity.txt; mode = "0400"; };
  };
}
