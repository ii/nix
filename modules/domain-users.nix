# domain-users.nix — The keystone module
#
# Declares domains and users, generates:
#   - Unix users and groups
#   - Group memberships (domain = group)
#   - Home directories
#   - SSH authorized keys
#   - Subdomain assignments (user.domain)
#
# Usage:
#   ii.domains = {
#     "ii.dev"    = { gid = 3000; };
#     "abcs.news" = { gid = 3001; };
#   };
#
#   ii.users = {
#     hh   = { uid = 1000; isHuman = true;  isAdmin = true; domains = ["dev"]; sshKeys = [...]; };
#     abcs = { uid = 2001; isHuman = false; domains = ["abcs"]; };
#   };
#
# This generates:
#   - Unix group "dev" (gid 3000) for ii.dev zone
#   - Unix group "abcs" (gid 3001) for abcs.news zone
#   - User hh (uid 1000) in groups [dev wheel]
#   - User abcs (uid 2001) as system user in group [abcs]
#   - hh gets subdomain hh.ii.dev (because hh is in group dev)
#   - abcs gets apex abcs.news (because abcs is a domain user)
#
# The generated config is available to other modules via:
#   config.ii.generated.subdomains  — { "hh" = ["hh.ii.dev"]; "abcs" = ["abcs.news"]; }
#   config.ii.generated.domainMap   — { "dev" = "ii.dev"; "abcs" = "abcs.news"; }

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.ii;

  # Build short-name -> full-domain map
  # e.g. { "dev" = "ii.dev"; "abcs" = "abcs.news"; }
  domainMap = mapAttrs' (fullDomain: domainCfg:
    let
      parts = splitString "." fullDomain;
      short = head parts;
    in
    nameValuePair short fullDomain
  ) cfg.domains;

  # Reverse: short-name -> domain config
  domainConfigByShort = mapAttrs' (fullDomain: domainCfg:
    nameValuePair (head (splitString "." fullDomain)) domainCfg
  ) cfg.domains;

  # For each user, compute their subdomains
  userSubdomains = mapAttrs (username: userCfg:
    if userCfg.isHuman then
      # Human users get user.domain for each domain group they're in
      map (short: "${username}.${domainMap.${short}}") userCfg.domains
    else
      # Service/domain users get the apex domain itself
      map (short: domainMap.${short}) userCfg.domains
  ) cfg.users;

  # For each user, compute their Unix groups
  userGroups = mapAttrs (username: userCfg:
    let
      domainGroups = userCfg.domains;
      adminGroups = optionals userCfg.isAdmin [ "wheel" ];
      baseGroups = optionals userCfg.isHuman [ "users" ];
    in
    domainGroups ++ adminGroups ++ baseGroups ++ userCfg.extraGroups
  ) cfg.users;

in
{
  options.ii = {
    # ===== Domain declarations =====
    domains = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          gid = mkOption {
            type = types.int;
            description = "Unix group ID for this domain's zone group";
          };

          description = mkOption {
            type = types.str;
            default = "";
            description = "Human-readable description of this domain";
          };
        };
      });
      default = {};
      description = ''
        Domain declarations. Each domain becomes a Unix group.
        The short name (first label) is the group name.
        Example: "ii.dev" -> group "dev" (gid from config)
      '';
    };

    # ===== User declarations =====
    users = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          uid = mkOption {
            type = types.int;
            description = "Unix user ID";
          };

          isHuman = mkOption {
            type = types.bool;
            default = true;
            description = ''
              Human users are interactive (shell, home-manager).
              Non-human users are service accounts (domain users).
            '';
          };

          isAdmin = mkOption {
            type = types.bool;
            default = false;
            description = "Admin users get wheel group (sudo)";
          };

          domains = mkOption {
            type = types.listOf types.str;
            default = [];
            description = ''
              Short names of domains this user belongs to.
              Example: ["dev"] means the user is in the "dev" group
              and gets a subdomain under ii.dev.
            '';
          };

          sshKeys = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "SSH public keys for this user";
          };

          shell = mkOption {
            type = types.package;
            default = pkgs.bash;
            description = "Login shell for this user";
          };

          extraGroups = mkOption {
            type = types.listOf types.str;
            default = [];
            description = "Additional Unix groups beyond domain memberships";
          };

          description = mkOption {
            type = types.str;
            default = "";
            description = "Human-readable description (GECOS field)";
          };

          home = mkOption {
            type = types.nullOr types.path;
            default = null;
            description = "Custom home directory. Defaults to /home/<user> or /var/lib/<user>";
          };
        };
      });
      default = {};
      description = ''
        User declarations. Each user gets a Unix account and
        subdomains based on their domain group memberships.
      '';
    };

    # ===== Generated outputs (read-only, used by other modules) =====
    generated = {
      subdomains = mkOption {
        type = types.attrsOf (types.listOf types.str);
        readOnly = true;
        default = userSubdomains;
        description = "Computed subdomains per user";
      };

      domainMap = mkOption {
        type = types.attrsOf types.str;
        readOnly = true;
        default = domainMap;
        description = "Short name -> full domain mapping";
      };

      allDomains = mkOption {
        type = types.listOf types.str;
        readOnly = true;
        default = attrNames cfg.domains;
        description = "All registered full domain names";
      };

      allSubdomains = mkOption {
        type = types.listOf types.str;
        readOnly = true;
        default = concatLists (attrValues userSubdomains);
        description = "All computed subdomains across all users";
      };
    };
  };

  config = mkIf (cfg.domains != {} || cfg.users != {}) {
    # ===== Generate Unix groups from domains =====
    users.groups = mapAttrs' (fullDomain: domainCfg:
      let short = head (splitString "." fullDomain);
      in nameValuePair short {
        gid = domainCfg.gid;
      }
    ) cfg.domains;

    # ===== Generate Unix users =====
    users.users = mapAttrs (username: userCfg:
      let
        homeDir =
          if userCfg.home != null then userCfg.home
          else if userCfg.isHuman then "/home/${username}"
          else "/srv/tenants/${username}";
      in
      {
        uid = userCfg.uid;
        isNormalUser = userCfg.isHuman;
        isSystemUser = !userCfg.isHuman;
        description = userCfg.description;
        home = homeDir;
        createHome = true;
        shell = userCfg.shell;
        extraGroups = userGroups.${username};
        openssh.authorizedKeys.keys = userCfg.sshKeys;
      } // optionalAttrs (!userCfg.isHuman) {
        # System users need an explicit group
        group = head userCfg.domains;
      }
    ) cfg.users;

    # ===== Ensure home directories exist with correct permissions =====
    systemd.tmpfiles.rules = concatLists (mapAttrsToList (username: userCfg:
      let
        homeDir =
          if userCfg.home != null then userCfg.home
          else if userCfg.isHuman then "/home/${username}"
          else "/srv/tenants/${username}";
        mode = if userCfg.isHuman then "0750" else "0700";
        group = if userCfg.isHuman then "users" else head userCfg.domains;
      in [
        "d ${homeDir} ${mode} ${username} ${group} -"
      ]
    ) cfg.users);
  };
}
