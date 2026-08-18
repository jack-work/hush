{
  description = "hush — a credential keeper";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = nixpkgs.legacyPackages.${system};
      });
    in
    {
      overlays.default = final: prev: {
        hush = final.buildGoModule rec {
          pname = "hush";
          version = "0.11.0";
          src = self;
          vendorHash = "sha256-lBR9vKupRfWpkSTZN0UZRBXWRsTvWRTsGXCmzaWwSZs=";
          subPackages = [ "." ];
          env.CGO_ENABLED = 0;

          # Surface the commit into the binary so `hush version` carries
          # something useful when built from a worktree.
          rev =
            if self ? rev then builtins.substring 0 12 self.rev
            else if self ? dirtyRev then builtins.substring 0 12 self.dirtyRev
            else "unknown";
          ldflags = [
            "-s" "-w"
            "-X github.com/jack-work/hush/internal/version.Version=${version}-${rev}"
          ];

          meta.mainProgram = "hush";
        };
      };

      packages = forAllSystems ({ pkgs }: rec {
        hush = (import nixpkgs {
          inherit (pkgs) system;
          overlays = [ self.overlays.default ];
        }).hush;
        default = hush;
      });

      # The agent as a socket-activated per-user service, for NixOS
      # nodes. The Arch/other-distro equivalent of this module is
      # `hush install-units`, which writes the same two units from
      # internal/units — keep them in step.
      #
      #   imports = [ hush.nixosModules.default ];
      #   services.hush-agent.enable = true;
      #
      # There is nothing to start at boot and nothing to log into: the
      # first client to touch the socket starts the agent, which unlocks
      # by whatever unlock.method the user's hush.toml names (on a
      # desktop node, the OS keyring; on a headless one, `exec`).
      nixosModules.default = { config, lib, pkgs, ... }:
        let cfg = config.services.hush-agent;
        in {
          options.services.hush-agent = {
            enable = lib.mkEnableOption
              "the socket-activated hush agent (a per-user service)";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.hush;
              defaultText = lib.literalExpression "hush.packages.\${system}.hush";
              description = "The hush package whose agent is started.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.user.sockets.hush-agent = {
              description = "hush agent socket";
              wantedBy = [ "sockets.target" ];
              socketConfig = {
                # The agent adopts this descriptor rather than binding
                # its own, so a client that arrives first waits in the
                # backlog instead of being refused.
                ListenStream = "%t/hush/agent.sock";
                SocketMode = "0600";
                DirectoryMode = "0700";
              };
            };

            systemd.user.services.hush-agent = {
              description = "hush agent";
              requires = [ "hush-agent.socket" ];
              after = [ "hush-agent.socket" ];
              serviceConfig = {
                Type = "exec";
                ExecStart = "${lib.getExe cfg.package} up";
                # The agent's TTL ends the process and the socket unit
                # re-arms; restarting would defeat the TTL, which exists
                # so decrypted key material is not resident all day.
                Restart = "no";
                Environment = [ "DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus" ];
              };
            };
          };
        };

      nixosModules.hush-agent = self.nixosModules.default;

      devShells = forAllSystems ({ pkgs }: let
        hushPkg = self.packages.${pkgs.system}.default;

        # Each knob is a single attribute on a profile. A null value
        # means "inherit from the real user environment" — the
        # corresponding env var is left untouched. A string means "set
        # this env var"; "@dev" is a sentinel expanded to a dev-scoped
        # path under $HUSH_DEV_ROOT/<knob>.
        #
        # The dev-shell knobs are:
        #
        #   config   → HUSH_CONFIG_DIR    (hush.toml, identity, commands/)
        #   state    → HUSH_STATE_DIR     (hush.log)
        #   runtime  → HUSH_RUNTIME_DIR   (agent.sock, agent.pid)
        #   keyring  → HUSH_KEYRING_SERVICE (keyring namespace; only
        #              meaningful once the keyring unlock method ships)
        #
        # All four default to "@dev" in the helper, so the helper
        # caller only overrides what they want to share. The named
        # presets at the bottom show common compositions.
        #
        # We deliberately do NOT touch XDG_CONFIG_HOME / XDG_STATE_HOME
        # / XDG_RUNTIME_DIR — those are session-wide and pre-set, so
        # overriding them with `${VAR:=...}` would silently no-op (the
        # caller already has them). HUSH_* takes priority over XDG_*
        # inside config/config.go.
        mkHushShell = {
          name,
          config  ? "@dev",
          state   ? "@dev",
          runtime ? "@dev",
          keyring ? "@dev",
        }: let
          mkKnob = envVar: subdir: value:
            if value == null then ''
              # ${envVar}: inheriting real user environment
            ''
            else if value == "@dev" then ''
              : "''${${envVar}:=$HUSH_DEV_ROOT/${subdir}}"
              export ${envVar}
              mkdir -p "''${${envVar}}"
            ''
            else ''
              : "''${${envVar}:=${value}}"
              export ${envVar}
            '';
          mkKeyringKnob = value:
            if value == null then ''
              # HUSH_KEYRING_SERVICE: inheriting (uses real "hush" service)
            ''
            else if value == "@dev" then ''
              : "''${HUSH_KEYRING_SERVICE:=hush-dev-${name}}"
              export HUSH_KEYRING_SERVICE
            ''
            else ''
              : "''${HUSH_KEYRING_SERVICE:=${value}}"
              export HUSH_KEYRING_SERVICE
            '';
        in pkgs.mkShell {
          inherit name;
          buildInputs = with pkgs; [
            go gopls gotools
          ] ++ [ hushPkg ];

          shellHook = ''
            export HUSH_DEV_ROOT="''${XDG_RUNTIME_DIR:-/tmp}/hush-dev-${name}"
            mkdir -p "$HUSH_DEV_ROOT"
            chmod 700 "$HUSH_DEV_ROOT"

            ${mkKnob "HUSH_CONFIG_DIR"  "config" config}
            ${mkKnob "HUSH_STATE_DIR"   "state"  state}
            ${mkKnob "HUSH_RUNTIME_DIR" "run"    runtime}
            ${mkKeyringKnob keyring}

            echo "[hush-dev:${name}] hush               = $(command -v hush)" >&2
            for v in HUSH_CONFIG_DIR HUSH_STATE_DIR HUSH_RUNTIME_DIR HUSH_KEYRING_SERVICE; do
              if [ -n "''${!v:-}" ]; then
                printf "[hush-dev:${name}] %-22s = %s\n" "$v" "''${!v}" >&2
              else
                printf "[hush-dev:${name}] %-22s = (inherited)\n" "$v" >&2
              fi
            done
          '';
        };
      in {
        # The default shell — every singleton inherited. The in-shell
        # `hush` is the worktree build (via buildInputs), so you're
        # testing your changes against your real data. Equivalent to
        # "I want to use my normal hush, but with the dev binary."
        default = mkHushShell {
          name = "default";
          config  = null;
          state   = null;
          runtime = null;
          keyring = null;
        };

        # Fully hermetic — every singleton path and the keyring
        # namespace are dev-scoped. First invocation will need
        # `hush init` to create an identity. Use this for testing
        # first-run UX or for completely blank-slate experiments.
        clean = mkHushShell { name = "clean"; };

        # Share the real identity (so you don't have to re-init or
        # re-add secrets) but isolate runtime + state so the dev
        # daemon doesn't collide with your live agent's socket.
        # Useful for daemon/agent changes against real data.
        share-identity = mkHushShell {
          name = "share-identity";
          config  = null;
          keyring = null;
        };

        # `nix develop .#swap` enters a shell that swaps the user's
        # installed hush for this worktree's build. The previous
        # profile entry is captured on entry and restored on exit, so
        # the shell behaves like a temporary "try this version" gate.
        #
        # On entry:
        #   1. Stop the running agent (`hush down`) so the swap doesn't
        #      leave a stale socket bound to the old binary.
        #   2. Find the current hush entry in the user's nix profile
        #      (by storePath match against "hush-VERSION"). Capture
        #      its key and originalUrl.
        #   3. Remove the captured entry; install this worktree's
        #      freshly-built hush by store path.
        #
        # On exit (bash EXIT trap):
        #   1. Stop the worktree agent.
        #   2. Remove the worktree entry from the profile.
        #   3. Reinstall the captured original entry, preferring its
        #      originalUrl so flake-tracking is preserved.
        #
        # Edge cases:
        #   - No existing hush in profile: skip save/restore.
        #   - jq absent: abort early.
        #   - SIGKILL of the shell: EXIT trap doesn't fire, profile
        #     stays on the worktree entry. Recover with a fresh
        #     `nix develop .#swap` + exit.
        swap = pkgs.mkShell {
          name = "hush-swap";
          buildInputs = with pkgs; [
            go gopls gotools
            jq nix
          ] ++ [ self.packages.${pkgs.system}.default ];

          HUSH_WORKTREE_PATH = "${self.packages.${pkgs.system}.default}";

          shellHook = ''
            set -u

            _hush_swap_find_entry() {
              nix profile list --json 2>/dev/null | jq -r '
                .elements | to_entries[]
                | select(.value.storePaths[]? | test("/[a-z0-9]+-hush-[0-9]+(\\.[0-9]+)*(-dev)?$"))
                | .key
              ' | head -1
            }

            _hush_swap_stop_agent() {
              if command -v hush >/dev/null 2>&1; then
                hush down >/dev/null 2>&1 || true
              fi
            }

            _hush_swap_enter() {
              if ! command -v jq >/dev/null 2>&1; then
                echo "[hush-swap] jq missing; aborting" >&2
                return 1
              fi

              local entry old_path old_url
              entry=$(_hush_swap_find_entry || true)
              if [ -n "$entry" ]; then
                old_path=$(nix profile list --json \
                  | jq -r --arg k "$entry" '.elements[$k].storePaths[0]')
                old_url=$(nix profile list --json \
                  | jq -r --arg k "$entry" '.elements[$k].originalUrl // empty')
                export HUSH_SWAP_OLD_KEY="$entry"
                export HUSH_SWAP_OLD_PATH="$old_path"
                export HUSH_SWAP_OLD_URL="$old_url"
                echo "[hush-swap] saving profile entry:" >&2
                echo "  key:  $entry" >&2
                echo "  path: $old_path" >&2
                [ -n "$old_url" ] && echo "  url:  $old_url" >&2
              else
                echo "[hush-swap] no hush in profile; nothing to restore on exit" >&2
              fi

              _hush_swap_stop_agent

              if [ -n "''${HUSH_SWAP_OLD_KEY:-}" ]; then
                nix profile remove "$HUSH_SWAP_OLD_KEY" >&2
              fi
              nix profile install "$HUSH_WORKTREE_PATH"
              echo "[hush-swap] worktree hush installed: $HUSH_WORKTREE_PATH" >&2
            }

            _hush_swap_exit() {
              echo "[hush-swap] exit — restoring previous hush" >&2
              _hush_swap_stop_agent

              local current
              current=$(nix profile list --json 2>/dev/null \
                | jq -r --arg p "$HUSH_WORKTREE_PATH" '
                    .elements | to_entries[]
                    | select(.value.storePaths[]? == $p)
                    | .key' | head -1)
              if [ -n "$current" ]; then
                nix profile remove "$current" >&2 || true
              fi

              if [ -n "''${HUSH_SWAP_OLD_URL:-}" ]; then
                nix profile install "$HUSH_SWAP_OLD_URL" >&2
                echo "[hush-swap] restored via flake url: $HUSH_SWAP_OLD_URL" >&2
              elif [ -n "''${HUSH_SWAP_OLD_PATH:-}" ]; then
                nix profile install "$HUSH_SWAP_OLD_PATH" >&2
                echo "[hush-swap] restored via store path: $HUSH_SWAP_OLD_PATH" >&2
              else
                echo "[hush-swap] nothing captured to restore" >&2
              fi
            }

            _hush_swap_enter
            trap _hush_swap_exit EXIT

            echo "[hush-swap] active — exit shell to restore the previous hush" >&2
          '';
        };
      });
    };
}
