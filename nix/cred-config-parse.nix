{ pkgs, self, nixpkgs }:
let
  hush = self.packages.${pkgs.stdenv.hostPlatform.system}.hush;
  instances = {
    anthropic-max.kind = "anthropic";
    anthropic-work = {
      kind = "refresh_token";
      clientId = "c";
      authorizeUrl = "https://claude.example/oauth/authorize";
      tokenUrl = "https://console.example/v1/oauth/token";
      redirectUri = "https://console.example/oauth/code/callback";
    };
  };
  rendered = extra: (nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      self.nixosModules.hush
      {
        boot.isContainer = true;
        system.stateVersion = "25.11";
        services.hush = {
          enable = true;
          recipient = "age1q420hq4mgxjlq2nw589e8hehfv3c6ld32z772qldwwlsvg89yqlqcgq8rd";
          identityFile = "/run/keys/hush-cred";
          inherit instances;
          credUsers = [ "root" ];
          dropUsers = [ "root" ];
        } // extra;
      }
    ];
  }).config.environment.etc."hush/config.toml".source;

  cases = {
    default = rendered { };
    narrowed = rendered { dropRefresh = [ "anthropic-work" ]; };
    no-refresh = rendered { dropRefresh = [ ]; };
  };

  refused = pkgs.writeText "refused.toml" ''
    recipient = "age1q420hq4mgxjlq2nw589e8hehfv3c6ld32z772qldwwlsvg89yqlqcgq8rd"
    [instances.a]
    kind = "anthropic"
    [principals.drop]
    users = ["root"]
    credentials = []
    login = true
    refresh = true
    socket = "/run/hush/drop.sock"
  '';
in
pkgs.runCommand "hush-cred-config-parse" { nativeBuildInputs = [ hush ]; } ''
  export HOME=$TMPDIR
  loads() {
    answer=$(hush cred serve --config "$1" --state-dir $TMPDIR/state --identity-file $TMPDIR/absent 2>&1) || true
    case "$answer" in
      *"cred config:"*) echo "$1 refused: $answer" >&2; return 1 ;;
      *"identity file:"*) return 0 ;;
      *) echo "$1 gave an unexpected answer: $answer" >&2; return 1 ;;
    esac
  }
  ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList (n: c: ''
    echo "case ${n}"
    loads ${c}
  '') cases)}
  if loads ${refused} 2>/dev/null; then
    echo "a refresh principal granting no instance loaded: the parse check cannot fail" >&2
    exit 1
  fi
  touch $out
''
