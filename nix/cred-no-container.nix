{ pkgs, self, nixpkgs }:
let
  eval = containers: nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      self.nixosModules.hush-cred
      {
        boot.isContainer = true;
        system.stateVersion = "25.11";
        services.hush-cred = {
          enable = true;
          recipient = "age1q420hq4mgxjlq2nw589e8hehfv3c6ld32z772qldwwlsvg89yqlqcgq8rd";
          identityFile = "/run/keys/hush-cred";
          instances.anthropic-work = {
            kind = "anthropic";
            clientId = "c";
            authorizeUrl = "https://claude.example/oauth/authorize";
            tokenUrl = "https://console.example/v1/oauth/token";
            redirectUri = "https://console.example/oauth/code/callback";
          };
        };
        inherit containers;
      }
    ];
  };
  failed = containers: map (a: a.message) (builtins.filter (a: !a.assertion) (eval containers).config.assertions);
  box = bindMounts: { box = { config = { }; inherit bindMounts; }; };
  binds = {
    socket-dir = box { "/run/hush-cred" = { }; };
    run = box { "/run" = { hostPath = "/run"; }; };
    renamed = box { "/minter" = { hostPath = "/run/hush-cred"; }; };
  };
  results = builtins.mapAttrs (_: failed) binds;
  missed = builtins.attrNames (pkgs.lib.filterAttrs (_: r: r == [ ]) results);
  clean = failed (box { "/srv/data" = { hostPath = "/srv/data"; }; });
in
assert pkgs.lib.assertMsg (missed == [ ]) "a container bind exposing the minter socket passed: ${toString missed}";
assert pkgs.lib.assertMsg (clean == [ ]) "an unrelated bind was refused: ${toString clean}";
pkgs.runCommand "hush-cred-no-container" { } "touch $out"
