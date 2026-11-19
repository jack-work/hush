self:
{ config, lib, pkgs, ... }:
let
  inherit (lib) mkOption types;

  layouts = {
    hush = {
      option = "services.hush";
      user = "hush";
      stateDir = "/var/lib/hush";
      runDir = "/run/hush";
      etcDir = "hush";
      service = "hush";
      fence = "hush-fence";
      table = "hush";
      socketUnit = name: "hush-${name}";
      rebindSockets = true;
    };
    hush-cred = {
      option = "services.hush-cred";
      user = "hush-cred";
      stateDir = "/var/lib/hush-cred";
      runDir = "/run/hush-cred";
      etcDir = "hush-cred";
      service = "hush-cred";
      fence = "hush-cred-fence";
      table = "hush_cred";
      socketUnit = name: "hush-cred-${name}";
      rebindSockets = false;
    };
  };

  reservedPrincipals = [ "cred" "drop" "admin" ];

  instanceType = types.submodule {
    options = {
      kind = mkOption { type = types.enum [ "anthropic" "refresh_token" "copilot" "chatgpt" "exec" ]; };
      clientId = mkOption { type = types.str; default = ""; };
      tokenUrl = mkOption { type = types.str; default = ""; };
      scopes = mkOption { type = types.str; default = ""; };
      authorizeUrl = mkOption { type = types.nullOr types.str; default = null; };
      redirectUri = mkOption { type = types.nullOr types.str; default = null; };
      deviceUrl = mkOption { type = types.nullOr types.str; default = null; };
      githubTokenUrl = mkOption { type = types.nullOr types.str; default = null; };
      audit = mkOption {
        type = types.bool;
        default = false;
        description = "Log one line per request for this credential (credential, principal, peer uid, status; never the token).";
      };
      command = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          kind = "exec" only: argv of a command that prints {"token", "expires_at"}; exit 3 = sign-in needed. It runs as
          the minter (its own uid, ProtectHome, inside the egress fence), so it can reach only the token endpoints:
          a tool that reads a user's own cache belongs in a hush cred serve run as that user.
        '';
      };
      timeout = mkOption { type = types.nullOr types.str; default = null; description = "kind = \"exec\" only (default 30s)."; };
    };
  };

  principalType = L: types.submodule ({ name, ... }: {
    options = {
      users = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "Users whose SO_PEERCRED uid may read on this principal's socket; each also gets a u:<user>:rw ACL on it.";
      };
      credentials = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Instances this principal may read. Anything else is refused (403 not_granted).";
      };
      login = mkOption {
        type = types.bool;
        default = false;
        description = "Allow the remote sign-in routes on this socket too.";
      };
      refresh = mkOption {
        type = types.bool;
        default = false;
        description = "Allow POST /refresh/<name> on this socket too. It answers status, never a token.";
      };
      socketPath = mkOption {
        type = types.str;
        default = "${L.runDir}/${name}.sock";
        description = "Where the principal's socket lives (0600 ${L.user}, plus one ACL entry per user).";
      };
    };
  });

  commonOptions = L: {
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.hush;
      defaultText = lib.literalExpression "hush.packages.\${system}.hush";
    };

    uid = mkOption {
      type = types.int;
      default = 476;
      description = "Static uid and gid of user ${L.user}; the egress fence matches on it.";
    };

    principals = mkOption {
      type = types.attrsOf (principalType L);
      default = { };
      description = "Callers with their own socket and grant list.";
    };

    consentGrants = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/var/lib/grants/grants.json";
      description = "Absolute path of a consent grants file ({\"grants\": [{id, principal, credential, expires_at, approved_by}]}), read at every request: a live row grants that credential to that principal beside its credentials list, audited per use. The minter's user must be able to read it. null: no consent grants.";
    };

    loginGate = mkOption {
      type = types.nullOr (types.submodule {
        options = {
          issuer = mkOption { type = types.str; description = "OpenID issuer URL (https); its discovery names the authorize, token and userinfo endpoints."; };
          clientId = mkOption { type = types.str; description = "Public OAuth2 client (PKCE S256)."; };
          group = mkOption { type = types.str; description = "Userinfo group the administrator must be in (name or name@domain)."; };
          redirectUri = mkOption { type = types.str; description = "Registered redirect: the code relay's callback."; };
          relay = mkOption { type = types.str; description = "GET <relay>?state=... answers the sign-in's code."; };
          maxAge = mkOption { type = types.str; default = "5m"; description = "Oldest accepted auth_time."; };
          wait = mkOption { type = types.str; default = "5m"; description = "How long login waits for the sign-in."; };
        };
      });
      default = null;
      description = "Gate `cred login` on a fresh administrator sign-in at an OpenID provider, before the credential's own login. null: no gate.";
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
      fence = mkOption {
        type = types.bool;
        default = true;
        description = "Confine the minter's uid to DNS and the resolved token endpoints (nftables). Needs a dnsmasq that fills the sets (egress.dnsmasq); turn it off on a host without one, or the minter reaches nothing.";
      };
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

    stateDir = mkOption {
      type = types.str;
      readOnly = true;
      default = L.stateDir;
    };

    unitGrants = mkOption {
      type = types.attrsOf (types.attrsOf types.str);
      default = { };
      example = { "keel-lieutenant.service".token = "ghe-read"; };
      description = ''
        LoadCredential grants by unit name: unitGrants."<unit>".<credential id> = "<instance>". The unit says
        LoadCredential=<credential id>:${L.runDir}/systemd.sock and receives the raw token. The socket believes the unit name
        only from systemd itself (peer uid 0). A refusal writes nothing, and systemd then starts the unit with an EMPTY
        credential file: the consumer must treat an empty credential as a failure. Empty: no socket.
      '';
    };

    systemdSocketPath = mkOption {
      type = types.str;
      readOnly = true;
      default = "${L.runDir}/systemd.sock";
      description = "The LoadCredential socket (0600 ${L.user}; systemd connects as root).";
    };
  };

  hushCfg = config.services.hush;
  oldCfg = config.services.hush-cred;

  hushSockets = let
    L = layouts.hush;
    builtin =
      lib.optionalAttrs (hushCfg.credUsers != [ ]) {
        cred = { users = hushCfg.credUsers; credentials = lib.attrNames hushCfg.instances; login = false; refresh = false; socketPath = hushCfg.socketPath; };
      }
      // lib.optionalAttrs (hushCfg.dropUsers != [ ]) {
        drop = { users = hushCfg.dropUsers; credentials = [ ]; login = true; refresh = true; socketPath = hushCfg.dropSocketPath; };
      };
  in {
    owner = { user = L.user; path = hushCfg.adminSocketPath; group = L.user; mode = "0600"; unit = L.socketUnit "admin"; fdName = "admin"; };
    principals = builtin // hushCfg.principals;
  };

  oldSockets = let L = layouts.hush-cred; in {
    owner = if oldCfg.allowUser == null then null else {
      user = oldCfg.allowUser; path = oldCfg.socketPath; group = oldCfg.socketGroup; mode = "0660"; unit = L.service; fdName = null;
    };
    principals = oldCfg.principals;
  };

  minter = L: cfg: sockets: let
    inherit (sockets) owner principals;
    configPath = "/etc/${L.etcDir}/config.toml";

    principalToml = p: {
      users = p.users;
      credentials = p.credentials;
      socket = p.socketPath;
    } // lib.optionalAttrs p.login { login = true; } // lib.optionalAttrs p.refresh { refresh = true; };

    instanceToml = i: lib.filterAttrs (_: v: v != null && v != "" && v != false) {
      kind = i.kind;
      client_id = i.clientId;
      token_url = i.tokenUrl;
      scopes = i.scopes;
      authorize_url = i.authorizeUrl;
      redirect_uri = i.redirectUri;
      device_url = i.deviceUrl;
      github_token_url = i.githubTokenUrl;
      audit = i.audit;
      command = if i.command == [ ] then null else i.command;
      timeout = i.timeout;
    };

    configFile = (pkgs.formats.toml { }).generate "${L.service}.toml" ({
      recipient = cfg.recipient;
      instances = lib.mapAttrs (_: instanceToml) cfg.instances;
    } // lib.optionalAttrs (owner != null) {
      allow_user = owner.user;
    } // lib.optionalAttrs (principals != { }) {
      principals = lib.mapAttrs (_: principalToml) principals;
    } // lib.optionalAttrs (cfg.unitGrants != { }) {
      systemd = { socket = cfg.systemdSocketPath; units = cfg.unitGrants; };
    } // lib.optionalAttrs (cfg.consentGrants != null) {
      consent_grants = cfg.consentGrants;
    } // lib.optionalAttrs (cfg.loginGate != null) {
      login_gate = with cfg.loginGate; {
        inherit issuer group relay wait;
        client_id = clientId;
        redirect_uri = redirectUri;
        max_age = maxAge;
      };
    });

    setfacl = "${pkgs.acl}/bin/setfacl";
    principalSockets = lib.mapAttrs' (pname: p: lib.nameValuePair (L.socketUnit pname) {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ p.socketPath ];
      socketConfig = {
        Service = "${L.service}.service";
        FileDescriptorName = pname;
        SocketUser = L.user;
        SocketGroup = L.user;
        SocketMode = "0600";
        DirectoryMode = "0755";
        # Access by uid, never by group: a group gate fails for a process whose user manager started before the user
        # joined the group. The SO_PEERCRED check in the server is the second, independent layer.
        ExecStartPost = map (u: "${setfacl} -m u:${u}:rw ${p.socketPath}") p.users;
      } // lib.optionalAttrs L.rebindSockets {
        RemoveOnStop = true;
      };
    }) principals;
    ownerSocket = lib.optionalAttrs (owner != null) { ${owner.unit} = {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ owner.path ];
      socketConfig = {
        SocketUser = L.user;
        SocketGroup = owner.group;
        SocketMode = owner.mode;
        DirectoryMode = "0755";
      } // lib.optionalAttrs L.rebindSockets {
        RemoveOnStop = true;
      } // lib.optionalAttrs (owner.unit != L.service) {
        Service = "${L.service}.service";
      } // lib.optionalAttrs (owner.fdName != null) {
        FileDescriptorName = owner.fdName;
      };
    }; };
    systemdSocket = lib.optionalAttrs (cfg.unitGrants != { }) { ${L.socketUnit "loadcredential"} = {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ cfg.systemdSocketPath ];
      socketConfig = {
        Service = "${L.service}.service";
        FileDescriptorName = "loadcredential";
        SocketUser = L.user;
        SocketGroup = L.user;
        # Only the system manager connects (root passes the mode); the server believes the unit name from uid 0 alone.
        SocketMode = "0600";
        DirectoryMode = "0755";
      } // lib.optionalAttrs L.rebindSockets {
        RemoveOnStop = true;
      };
    }; };
    socketUnits = lib.attrNames ownerSocket ++ lib.attrNames principalSockets ++ lib.attrNames systemdSocket;
    allSocketPaths = lib.optional (owner != null) owner.path ++ map (p: p.socketPath) (lib.attrValues principals)
      ++ lib.optional (cfg.unitGrants != { }) cfg.systemdSocketPath;

    pinnedTokenUrl = {
      chatgpt = "https://auth.openai.com/oauth/token";
      anthropic = "https://console.anthropic.com/v1/oauth/token";
    };

    egressUrls = lib.concatMap (i: if i.kind == "exec" then [ ] else if pinnedTokenUrl ? ${i.kind} then [ pinnedTokenUrl.${i.kind} ] else lib.filter (u: u != null) [ i.tokenUrl i.deviceUrl i.githubTokenUrl ])
      (lib.attrValues cfg.instances);
    hostOf = u: let m = builtins.match "https://([a-zA-Z0-9.-]+)(/.*)?" u; in if m == null then null else lib.head m;
    egressHosts = lib.unique (lib.filter (h: h != null) (map hostOf egressUrls));

    fence = pkgs.writeText "${L.fence}.nft" ''
      table inet ${L.table}
      delete table inet ${L.table}
      table inet ${L.table} {
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

    stripSlash = s:
      if s != "/" && lib.hasSuffix "/" s then stripSlash (lib.removeSuffix "/" s) else s;
    exposes = raw:
      let p = stripSlash raw; in
      p != "" && (
        p == "/"
        || lib.any (sp: p == sp || lib.hasPrefix (p + "/") sp || lib.hasPrefix (dirOf sp + "/") p) allSocketPaths
      );

    hush = lib.getExe cfg.package;
    who = lib.concatStringsSep ", " (lib.optional (owner != null) owner.user ++ lib.attrNames principals);
  in {
    assertions = [
      {
        assertion = lib.all (u: hostOf u != null) egressUrls;
        message = "${L.option}: every token, device and GitHub URL must be https on port 443 (the fence opens 443 only): ${toString egressUrls}";
      }
      {
        assertion = cfg.instances != { };
        message = "${L.option}: no instances";
      }
      {
        assertion = owner != null || principals != { };
        message = "${L.option}: set allowUser or at least one principal";
      }
      {
        assertion = !(principals ? loadcredential);
        message = "${L.option}: principal loadcredential is reserved for the LoadCredential socket";
      }
    ] ++ lib.concatLists (lib.mapAttrsToList (unit: grants: lib.mapAttrsToList (id: c: {
      assertion = cfg.instances ? ${c};
      message = "${L.option}: unitGrants.${unit}.${id} grants ${c}, which is not an instance";
    }) grants) cfg.unitGrants) ++ lib.concatLists (lib.mapAttrsToList (pname: p: map (c: {
      assertion = cfg.instances ? ${c};
      message = "${L.option}: principal ${pname} grants ${c}, which is not an instance";
    }) p.credentials) principals) ++ lib.concatLists (lib.mapAttrsToList (name: c: map (b: let p = if b.hostPath == null then b.mountPoint else toString b.hostPath; in {
      assertion = !(exposes p);
      message = "${L.option}: container ${name} binds ${p}, which holds the minter's socket; it is bound into no container";
    }) (lib.attrValues c.bindMounts)) config.containers);

    users.users.${L.user} = {
      isSystemUser = true;
      uid = cfg.uid;
      group = L.user;
      home = L.stateDir;
    };
    users.groups.${L.user}.gid = cfg.uid;

    environment.etc."${L.etcDir}/config.toml".source = configFile;
    environment.systemPackages = [
      (pkgs.writeShellScriptBin "hush-cred" ''
        case "''${1-}" in
          login|serve) sub=$1; shift; exec ${hush} cred "$sub" --config ${configPath} --state-dir ${L.stateDir} "$@" ;;
          *) exec ${hush} cred "$@" ;;
        esac
      '')
    ];

    services.dnsmasq.settings.nftset = lib.mkIf (cfg.egress.fence && cfg.egress.dnsmasq) [
      "/${lib.concatStringsSep "/" egressHosts}/4#inet#${L.table}#allow4,6#inet#${L.table}#allow6"
    ];

    systemd.services.${L.fence} = lib.mkIf cfg.egress.fence {
      description = "the ${L.service} egress fence: uid ${toString cfg.uid} reaches DNS and resolved token endpoints only";
      wantedBy = [ "multi-user.target" ];
      before = [ "${L.service}.service" "dnsmasq.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${pkgs.nftables}/bin/nft -f ${fence}";
        ExecStop = "${pkgs.nftables}/bin/nft delete table inet ${L.table}";
      };
    };

    systemd.sockets = principalSockets // ownerSocket // systemdSocket;

    systemd.services.${L.service} = let
      sockets = map (u: "${u}.socket") socketUnits;
    in {
      description = "hush cred serve: plan credentials for ${who}";
      wantedBy = [ "multi-user.target" ];
      requires = sockets ++ lib.optional cfg.egress.fence "${L.fence}.service";
      after = sockets ++ lib.optional cfg.egress.fence "${L.fence}.service" ++ [ "network-online.target" "dnsmasq.service" ];
      wants = [ "network-online.target" ];
      restartTriggers = [ configFile ];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${hush} cred serve --config ${configPath} --state-dir ${L.stateDir} --identity-file %d/identity";
        User = L.user;
        Group = L.user;
        StateDirectory = lib.removePrefix "/var/lib/" L.stateDir;
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
      } // lib.optionalAttrs L.rebindSockets {
        Sockets = sockets;
        X-NotSocketActivated = true;
      };
    };
  };
in
{
  key = "hush/nix/cred-module.nix";

  options.services.hush = commonOptions layouts.hush // {
    enable = lib.mkEnableOption "hush as a system service: the plan-credential minter, its drop box and its admin socket";

    credUsers = mkOption {
      type = types.listOf types.str;
      default = [ "figaro" ];
      description = ''
        Users whose SO_PEERCRED uid may read any instance on the cred socket (GET /cred/<name> only). Each gets a
        u:<user>:rw ACL on it; group membership grants nothing. Empty: no cred socket.
      '';
    };

    dropUsers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Users who may sign an instance in or refresh it on the drop box (POST /login-start/<name>,
        /login-complete/<name>, /refresh/<name>). The drop box answers status, never a token. Empty: no drop box.
      '';
    };

    socketPath = mkOption {
      type = types.str;
      readOnly = true;
      default = "${layouts.hush.runDir}/cred.sock";
      description = "The cred socket; a figaro provider's [cred] socket points here.";
    };

    dropSocketPath = mkOption {
      type = types.str;
      readOnly = true;
      default = "${layouts.hush.runDir}/drop.sock";
    };

    adminSocketPath = mkOption {
      type = types.str;
      readOnly = true;
      default = "${layouts.hush.runDir}/admin.sock";
      description = "0600 ${layouts.hush.user}; root reaches it with runuser -u ${layouts.hush.user}. Status, refresh and sign-in.";
    };
  };

  options.services.hush-cred = commonOptions layouts.hush-cred // {
    enable = lib.mkEnableOption "services.hush under its old names (user hush-cred, /var/lib/hush-cred), kept for one release";

    allowUser = mkOption {
      type = types.nullOr types.str;
      default = "rou2";
      description = "The one user whose SO_PEERCRED uid may read every credential on ${layouts.hush-cred.runDir}/cred.sock. null: no such socket (principals only).";
    };

    socketGroup = mkOption {
      type = types.str;
      default = "rou2";
      description = "Group of the 0660 socket.";
    };

    socketPath = mkOption {
      type = types.str;
      readOnly = true;
      default = "${layouts.hush-cred.runDir}/cred.sock";
    };
  };

  options.services.restic.backups = mkOption {
    type = types.attrsOf (types.submodule {
      config.exclude = lib.optional hushCfg.enable layouts.hush.stateDir
        ++ lib.optional oldCfg.enable layouts.hush-cred.stateDir;
    });
  };

  config = lib.mkMerge [
    {
      assertions = [{
        assertion = !(hushCfg.enable && oldCfg.enable);
        message = "services.hush and services.hush-cred are one minter under two names (uid ${toString hushCfg.uid}); enable one";
      }];
    }
    (lib.mkIf hushCfg.enable (lib.mkMerge [
      (minter layouts.hush hushCfg hushSockets)
      {
        assertions = map (n: {
          assertion = !(hushCfg.principals ? ${n});
          message = "services.hush: principal ${n} is reserved for the ${n} socket";
        }) reservedPrincipals;
      }
    ]))
    (lib.mkIf oldCfg.enable (lib.mkMerge [
      (minter layouts.hush-cred oldCfg oldSockets)
      {
        users.groups.${oldCfg.socketGroup} = { };
        warnings = [
          "services.hush-cred is services.hush under its old names and goes in the next release; move during a window, as docs/hush-system-service.md says (state moved, never copied)."
        ];
      }
    ]))
  ];
}
