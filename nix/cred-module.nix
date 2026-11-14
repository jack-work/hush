self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.hush-cred;
  inherit (lib) mkOption types;

  stateDir = "/var/lib/hush-cred";
  socketPath = "/run/hush-cred/cred.sock";
  configPath = "/etc/hush-cred/config.toml";
  table = "hush_cred";

  instanceType = types.submodule {
    options = {
      kind = mkOption { type = types.enum [ "anthropic" "copilot" ]; };
      clientId = mkOption { type = types.str; };
      tokenUrl = mkOption { type = types.str; };
      scopes = mkOption { type = types.str; default = ""; };
      authorizeUrl = mkOption { type = types.nullOr types.str; default = null; };
      redirectUri = mkOption { type = types.nullOr types.str; default = null; };
      deviceUrl = mkOption { type = types.nullOr types.str; default = null; };
      githubTokenUrl = mkOption { type = types.nullOr types.str; default = null; };
    };
  };

  instanceToml = i: lib.filterAttrs (_: v: v != null && v != "") {
    kind = i.kind;
    client_id = i.clientId;
    token_url = i.tokenUrl;
    scopes = i.scopes;
    authorize_url = i.authorizeUrl;
    redirect_uri = i.redirectUri;
    device_url = i.deviceUrl;
    github_token_url = i.githubTokenUrl;
  };

  configFile = (pkgs.formats.toml { }).generate "hush-cred.toml" {
    recipient = cfg.recipient;
    allow_user = cfg.allowUser;
    instances = lib.mapAttrs (_: instanceToml) cfg.instances;
  };

  egressUrls = lib.concatMap (i: lib.filter (u: u != null) [ i.tokenUrl i.deviceUrl i.githubTokenUrl ])
    (lib.attrValues cfg.instances);
  hostOf = u: let m = builtins.match "https://([a-zA-Z0-9.-]+)(/.*)?" u; in if m == null then null else lib.head m;
  egressHosts = lib.unique (lib.filter (h: h != null) (map hostOf egressUrls));

  fence = pkgs.writeText "hush-cred-fence.nft" ''
    table inet ${table}
    delete table inet ${table}
    table inet ${table} {
      set allow4 { type ipv4_addr; }
      set allow6 { type ipv6_addr; }
      chain out {
        type filter hook output priority 0; policy accept;
        meta skuid != ${toString cfg.uid} accept
        ct state established,related accept
        ${lib.concatMapStrings (r: ''
          ${if lib.hasInfix ":" r then "ip6" else "ip"} daddr ${r} meta l4proto { tcp, udp } th dport 53 accept
        '') cfg.egress.resolvers}
        ip daddr @allow4 tcp dport 443 accept
        ip6 daddr @allow6 tcp dport 443 accept
        counter reject
      }
    }
  '';

  exposes = p: p != "" && (p == "/" || lib.hasPrefix (dirOf socketPath) p || lib.hasPrefix (p + "/") socketPath);

  hush = lib.getExe cfg.package;
in
{
  options.services.hush-cred = {
    enable = lib.mkEnableOption "hush cred serve, the plan-credential minter for one local uid";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.hush;
      defaultText = lib.literalExpression "hush.packages.\${system}.hush";
    };

    uid = mkOption {
      type = types.int;
      default = 476;
      description = "Static uid and gid of the minter; the egress fence matches on it.";
    };

    allowUser = mkOption {
      type = types.str;
      default = "rou2";
      description = "The one user whose SO_PEERCRED uid may read /cred.";
    };

    socketGroup = mkOption {
      type = types.str;
      default = "rou2";
      description = "Group of the 0660 socket.";
    };

    recipient = mkOption {
      type = types.strMatching "age1[0-9a-z]+";
      description = "Public half of the identity: login encrypts to it without holding the key.";
    };

    identityFile = mkOption {
      type = types.str;
      description = "Host path of the age identity, handed to the unit alone by LoadCredential.";
    };

    instances = mkOption {
      type = types.attrsOf instanceType;
      default = { };
    };

    egress = {
      resolvers = mkOption {
        type = types.listOf types.str;
        default = [ "127.0.0.1" ];
        description = "The DNS servers the minter may ask; they must be the dnsmasq that fills the fence's sets.";
      };
      dnsmasq = mkOption {
        type = types.bool;
        default = true;
        description = "Have services.dnsmasq add every address it resolves for a token endpoint to the fence.";
      };
    };

    socketPath = mkOption {
      type = types.str;
      readOnly = true;
      default = socketPath;
    };

    stateDir = mkOption {
      type = types.str;
      readOnly = true;
      default = stateDir;
    };
  };

  options.services.restic.backups = mkOption {
    type = types.attrsOf (types.submodule {
      config.exclude = lib.mkIf cfg.enable [ stateDir ];
    });
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.all (u: hostOf u != null) egressUrls;
        message = "services.hush-cred: every token, device and GitHub URL must be https on port 443 (the fence opens 443 only): ${toString egressUrls}";
      }
      {
        assertion = cfg.instances != { };
        message = "services.hush-cred: no instances";
      }
    ] ++ lib.concatLists (lib.mapAttrsToList (name: c: map (b: let p = if b.hostPath == null then b.mountPoint else toString b.hostPath; in {
      assertion = !(exposes p);
      message = "services.hush-cred: container ${name} binds ${p}, which holds the minter's socket; it is bound into no container";
    }) (lib.attrValues c.bindMounts)) config.containers);

    users.users.hush-cred = {
      isSystemUser = true;
      uid = cfg.uid;
      group = "hush-cred";
      home = stateDir;
    };
    users.groups.hush-cred.gid = cfg.uid;
    users.groups.${cfg.socketGroup} = { };

    environment.etc."hush-cred/config.toml".source = configFile;
    environment.systemPackages = [
      (pkgs.writeShellScriptBin "hush-cred" ''exec ${hush} cred "$@"'')
    ];

    services.dnsmasq.settings.nftset = lib.mkIf cfg.egress.dnsmasq [
      "/${lib.concatStringsSep "/" egressHosts}/4#inet#${table}#allow4,6#inet#${table}#allow6"
    ];

    systemd.services.hush-cred-fence = {
      description = "the hush-cred egress fence: uid ${toString cfg.uid} reaches DNS and resolved token endpoints only";
      wantedBy = [ "multi-user.target" ];
      before = [ "hush-cred.service" "dnsmasq.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.nftables}/bin/nft -f ${fence}";
        ExecStop = "${pkgs.nftables}/bin/nft delete table inet ${table}";
      };
    };

    systemd.sockets.hush-cred = {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ socketPath ];
      socketConfig = {
        SocketUser = "hush-cred";
        SocketGroup = cfg.socketGroup;
        SocketMode = "0660";
        DirectoryMode = "0755";
      };
    };

    systemd.services.hush-cred = {
      description = "hush cred serve: plan credentials for ${cfg.allowUser}";
      wantedBy = [ "multi-user.target" ];
      requires = [ "hush-cred.socket" "hush-cred-fence.service" ];
      after = [ "hush-cred.socket" "hush-cred-fence.service" "network-online.target" "dnsmasq.service" ];
      wants = [ "network-online.target" ];
      restartTriggers = [ configFile ];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${hush} cred serve --config ${configPath} --state-dir ${stateDir} --identity-file %d/identity";
        User = "hush-cred";
        Group = "hush-cred";
        StateDirectory = "hush-cred";
        StateDirectoryMode = "0700";
        LoadCredential = [ "identity:${cfg.identityFile}" ];
        Restart = "on-failure";
        RestartSec = 5;
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        DevicePolicy = "closed";
        PrivateIPC = true;
        RemoveIPC = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
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
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        MemoryMax = "128M";
        TasksMax = 64;
      };
    };
  };
}
