self:
{ config, lib, pkgs, ... }:
let
  inherit (lib) mkOption types;
  cfg = config.services.hush-workload;
  hush = "${cfg.package}/bin/hush";
in
{
  options.services.hush-workload = {
    enable = lib.mkEnableOption "the hush workload socket: SVIDs for attested local processes";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "hush.packages.\${system}.default";
    };

    trustDomain = mkOption {
      type = types.strMatching "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
      description = "The troupe.";
    };

    node = mkOption {
      type = types.strMatching "[A-Za-z0-9._-]+";
      description = "This node's name, as its intermediate names it.";
    };

    rootCert = mkOption {
      type = types.path;
      description = "The troupe root certificate (public).";
    };

    intermediateCert = mkOption {
      type = types.path;
      description = "This node's intermediate certificate (public).";
    };

    intermediateKey = mkOption {
      type = types.str;
      description = "Host path of the intermediate's private key, handed to the unit alone by LoadCredential. Never a store path.";
    };

    jwtKey = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Host path of an ECDSA P-256 key for JWT-SVIDs, by LoadCredential. Null refuses JWT-SVIDs.";
    };

    socketPath = mkOption {
      type = types.str;
      readOnly = true;
      default = "/run/hush/workload.sock";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(lib.hasPrefix builtins.storeDir cfg.intermediateKey);
        message = "services.hush-workload.intermediateKey is in the world-readable store; give a host path";
      }
      {
        assertion = cfg.jwtKey == null || !(lib.hasPrefix builtins.storeDir cfg.jwtKey);
        message = "services.hush-workload.jwtKey is in the world-readable store; give a host path";
      }
    ];

    systemd.sockets.hush-workload = {
      description = "hush workload socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = cfg.socketPath;
        SocketMode = "0666";
        DirectoryMode = "0755";
        Accept = false;
      };
    };

    systemd.services.hush-workload = {
      description = "hush workload: SVIDs for ${cfg.trustDomain} node ${cfg.node}";
      requires = [ "hush-workload.socket" ];
      after = [ "hush-workload.socket" ];
      serviceConfig = {
        Type = "exec";
        ExecStart = lib.concatStringsSep " " ([
          hush "workload" "serve"
          "--trust-domain" cfg.trustDomain
          "--node" cfg.node
          "--root-cert" "${cfg.rootCert}"
          "--intermediate-cert" "${cfg.intermediateCert}"
          "--intermediate-key" "%d/intermediate"
        ] ++ lib.optionals (cfg.jwtKey != null) [ "--jwt-key" "%d/jwt" ]);
        LoadCredential = [ "intermediate:${cfg.intermediateKey}" ]
          ++ lib.optional (cfg.jwtKey != null) "jwt:${cfg.jwtKey}";
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 5;
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        DevicePolicy = "closed";
        PrivateNetwork = true;
        IPAddressDeny = "any";
        PrivateIPC = true;
        RemoveIPC = true;
        PrivateUsers = false;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "default";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
        SystemCallErrorNumber = "EPERM";
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        RestrictAddressFamilies = [ "AF_UNIX" ];
        MemoryMax = "64M";
        TasksMax = 32;
      };
    };
  };
}
