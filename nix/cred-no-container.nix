{ pkgs, self, nixpkgs }:
let
  instances.anthropic-work = {
    kind = "anthropic";
    clientId = "c";
    authorizeUrl = "https://claude.example/oauth/authorize";
    tokenUrl = "https://console.example/v1/oauth/token";
    redirectUri = "https://console.example/oauth/code/callback";
  };
  minter = {
    enable = true;
    recipient = "age1q420hq4mgxjlq2nw589e8hehfv3c6ld32z772qldwwlsvg89yqlqcgq8rd";
    identityFile = "/run/keys/hush-cred";
    inherit instances;
  };
  eval = module: extra: nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      self.nixosModules.${module}
      {
        boot.isContainer = true;
        system.stateVersion = "25.11";
      }
      extra
    ];
  };
  failedWith = module: extra: map (a: a.message) (builtins.filter (a: !a.assertion) (eval module extra).config.assertions);

  old = containers: failedWith "hush-cred" { services.hush-cred = minter; inherit containers; };
  new = containers: failedWith "hush" { services.hush = minter // { dropUsers = [ "root" ]; }; inherit containers; };

  box = bindMounts: { box = { config = { }; inherit bindMounts; }; };
  oldBinds = {
    socket-dir = box { "/run/hush-cred" = { }; };
    dir-slash = box { "/minter" = { hostPath = "/run/hush-cred/"; }; };
    direct-sock = box { "/sock" = { hostPath = "/run/hush-cred/cred.sock"; }; };
    run = box { "/run" = { hostPath = "/run"; }; };
    run-slash = box { "/run" = { hostPath = "/run/"; }; };
    renamed = box { "/minter" = { hostPath = "/run/hush-cred"; }; };
  };
  newBinds = {
    socket-dir = box { "/run/hush" = { }; };
    dir-slash = box { "/minter" = { hostPath = "/run/hush/"; }; };
    cred-sock = box { "/sock" = { hostPath = "/run/hush/cred.sock"; }; };
    drop-sock = box { "/sock" = { hostPath = "/run/hush/drop.sock"; }; };
    admin-sock = box { "/sock" = { hostPath = "/run/hush/admin.sock"; }; };
    run = box { "/run" = { hostPath = "/run"; }; };
  };
  missed = check: binds: builtins.attrNames (pkgs.lib.filterAttrs (_: r: r == [ ]) (builtins.mapAttrs (_: check) binds));
  missedOld = missed old oldBinds;
  missedNew = missed new newBinds;
  clean = old (box { "/srv/data" = { hostPath = "/srv/data"; }; })
    ++ old (box { "/other" = { hostPath = "/run/hush-cred-other"; }; })
    ++ new (box { "/srv/data" = { hostPath = "/srv/data"; }; })
    ++ new (box { "/other" = { hostPath = "/run/hush-other"; }; });

  reserved = failedWith "hush" { services.hush = minter // { principals.drop = { users = [ "root" ]; credentials = [ "anthropic-work" ]; }; }; };
  both = failedWith "hush" { imports = [ self.nixosModules.hush-cred ]; services.hush = minter; services.hush-cred = minter; };
  oldWarns = (eval "hush-cred" { services.hush-cred = minter; }).config.warnings;
  newWarns = (eval "hush" { services.hush = minter; }).config.warnings;
in
assert pkgs.lib.assertMsg (missedOld == [ ]) "services.hush-cred: a container bind exposing the minter socket passed: ${toString missedOld}";
assert pkgs.lib.assertMsg (missedNew == [ ]) "services.hush: a container bind exposing a minter socket passed: ${toString missedNew}";
assert pkgs.lib.assertMsg (clean == [ ]) "an unrelated bind was refused: ${toString clean}";
assert pkgs.lib.assertMsg (reserved != [ ]) "services.hush accepted a principal named drop";
assert pkgs.lib.assertMsg (both != [ ]) "services.hush and services.hush-cred were both enabled";
assert pkgs.lib.assertMsg (pkgs.lib.any (pkgs.lib.hasPrefix "services.hush-cred is services.hush") oldWarns) "the old name gave no deprecation warning";
assert pkgs.lib.assertMsg (!(pkgs.lib.any (pkgs.lib.hasInfix "hush") newWarns)) "the new name warned";
pkgs.runCommand "hush-cred-no-container" { } "touch $out"
