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
#     # Federation member — uid + sshKeys auto-resolved from GitHub identity:
#     hh   = { federation = true; isAdmin = true; domains = ["dev"]; };
#
#     # Service user (tenant) — manual uid, no federation:
#     abcs = { uid = 2001; isHuman = false; domains = ["abcs"]; };
#   };
#
# FEDERATION USERS (federation = true):
#   - uid auto-resolved from `federationRegistry` below (raw GitHub numeric ID)
#   - sshKeys fetched at runtime from https://github.com/<login>.keys via
#     services.openssh.authorizedKeysCommand (always-fresh; revocation propagates;
#     no IFD; no committed snapshot to drift)
#   - inline `sshKeys = [...]` must be empty (assertion enforces this)
#   - implicit isHuman = true (assertion enforces — service users can't be
#     federation; orgs don't have personal SSH keys)
#   - githubLogin defaults to the attribute name; override only if Unix username
#     differs from GH login
#
# Adding a federation member: append to `federationRegistry` with their GH ID:
#   curl -sS https://api.github.com/users/<login> | jq -r '.id'
# Append-only; removal requires explicit architectural decision.

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.ii;

  # ===== Federation registry — single source of truth =====
  # UID = raw GitHub numeric user ID. No offset, no override mechanism (YAGNI
  # per Gen 1 architect endorsement, director-decided 2026-05-01).
  federationRegistry = {
    hh = { uid = 31331; description = "Hippie Hacker"; };
    hal9000 = { uid = 24932; description = "Hal Fulton"; };
    # As federation grows, append (architectural decision per addition):
    #   ash    = { uid = <gh-id>; description = "Ash"; };
    #   ben    = { uid = <gh-id>; description = "Ben"; };
  };

  # Resolve a user's githubLogin (explicit or default to attr name)
  ghLogin = username: userCfg:
    if userCfg.githubLogin != null then userCfg.githubLogin else username;

  # Federation users get uid + description from the registry; their inline
  # uid/description are ignored if set. Non-federation users pass through.
  resolveUser = username: userCfg:
    if userCfg.federation then
      let
        login = ghLogin username userCfg;
        regEntry = federationRegistry.${login};
      in
      userCfg // {
        uid = regEntry.uid;
        description =
          if userCfg.description == "" then regEntry.description else userCfg.description;
        sshKeys = [];  # runtime fetch; inline list must be empty
      }
    else
      userCfg;

  # Apply federation resolution to every user before computing groups/subdomains
  resolvedUsers = mapAttrs resolveUser cfg.users;

  # Build short-name -> full-domain map
  domainMap = mapAttrs' (fullDomain: _:
    let short = head (splitString "." fullDomain);
    in nameValuePair short fullDomain
  ) cfg.domains;

  # For each user, compute their subdomains
  userSubdomains = mapAttrs (username: userCfg:
    if userCfg.isHuman then
      map (short: "${username}.${domainMap.${short}}") userCfg.domains
    else
      map (short: domainMap.${short}) userCfg.domains
  ) resolvedUsers;

  # For each user, compute their Unix groups
  userGroups = mapAttrs (username: userCfg:
    let
      domainGroups = userCfg.domains;
      adminGroups = optionals userCfg.isAdmin [ "wheel" ];
      baseGroups = optionals userCfg.isHuman [ "users" ];
    in
    domainGroups ++ adminGroups ++ baseGroups ++ userCfg.extraGroups
  ) resolvedUsers;

  # Whether ANY user is a federation member — gates the authorizedKeysCommand
  hasFederationUsers = any (u: u.federation) (attrValues cfg.users);

  # Runtime SSH-keys fetcher — sshd calls this per login attempt for
  # federation users. Non-federation users are unaffected (script exits 0
  # producing no keys → sshd falls through to standard authorized_keys).
  federationKeysFetcher = pkgs.writeShellScript "federation-authorized-keys" ''
    set -eu
    user="$1"
    # Map Unix username to GH login (defaults to same; override via githubLogin)
    case "$user" in
      ${concatStringsSep "\n      "
        (mapAttrsToList (username: userCfg:
          if userCfg.federation then
            ''${username}) login="${ghLogin username userCfg}" ;;''
          else ""
        ) cfg.users)}
      *) exit 0 ;;
    esac
    ${pkgs.curl}/bin/curl -fsSL "https://github.com/$login.keys"
  '';

in
{
  options.ii = {
    # ===== Domain declarations (unchanged) =====
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

    # ===== User declarations (federation fields added) =====
    users = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          # ----- NEW: federation identity -----
          federation = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Mark this user as a federation member. When true:
                - uid auto-resolved from federationRegistry (raw GH numeric ID)
                - sshKeys fetched at runtime from github.com/<login>.keys
                - inline sshKeys must be empty (assertion)
                - isHuman must be true (assertion — orgs aren't federation members)
                - description defaults from registry if not set
            '';
          };

          githubLogin = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              GitHub login for federation identity. Defaults to the user's
              attribute name when federation=true. Override only if the Unix
              username differs from the GitHub login.
            '';
          };

          # ----- Existing fields (uid now optional for federation users) -----
          uid = mkOption {
            type = types.nullOr types.int;
            default = null;
            description = ''
              Unix user ID. Required for non-federation users.
              For federation users this is auto-resolved from the registry;
              setting it here is ignored.
            '';
          };

          isHuman = mkOption {
            type = types.bool;
            default = true;
            description = ''
              Human users are interactive (shell, home-manager).
              Non-human users are service accounts (domain users).
              Must be true for federation=true users.
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
            description = ''
              SSH public keys for this user. MUST be empty for
              federation=true users (their keys are fetched at runtime).
            '';
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

    # ===== Generated outputs (now computed from resolvedUsers) =====
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
    # ===== Assertions: federation invariants =====
    assertions =
      (mapAttrsToList (username: userCfg: {
        assertion = !(userCfg.federation && userCfg.sshKeys != []);
        message = ''
          ii.users.${username} has federation=true AND inline sshKeys.
          Federation users get keys via runtime fetch from GitHub; the
          inline list must be empty.
        '';
      }) cfg.users)
      ++
      (mapAttrsToList (username: userCfg: {
        assertion = !(userCfg.federation && !userCfg.isHuman);
        message = ''
          ii.users.${username} has federation=true AND isHuman=false.
          Federation members are humans (orgs/services don't have personal
          SSH keys to fetch). Service users use manual uid + no federation flag.
        '';
      }) cfg.users)
      ++
      (mapAttrsToList (username: userCfg: {
        assertion =
          if userCfg.federation then
            federationRegistry ? ${ghLogin username userCfg}
          else true;
        message = ''
          ii.users.${username} has federation=true but '${ghLogin username userCfg}'
          is not in federationRegistry. Add their GitHub numeric user ID
          to federationRegistry in modules/domain-users.nix first.
            Lookup: curl -sS https://api.github.com/users/${ghLogin username userCfg} | jq -r '.id'
        '';
      }) cfg.users)
      ++
      (mapAttrsToList (username: userCfg: {
        assertion = userCfg.federation || userCfg.uid != null;
        message = ''
          ii.users.${username}: non-federation users must declare an explicit uid.
        '';
      }) cfg.users);

    # ===== Generate Unix groups from domains =====
    users.groups = mapAttrs' (fullDomain: domainCfg:
      let short = head (splitString "." fullDomain);
      in nameValuePair short {
        gid = domainCfg.gid;
      }
    ) cfg.domains;

    # ===== Generate Unix users (using resolved federation identities) =====
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
        group = head userCfg.domains;
      }
    ) resolvedUsers;

    # ===== Federation runtime SSH-keys fetcher =====
    # Only wires services.openssh.authorizedKeysCommand if there's at least
    # one federation user on this machine; otherwise sshd's default behavior
    # (read ~/.ssh/authorized_keys per user) is preserved unchanged.
    #
    # IMPORTANT: sshd's safe_path check refuses to invoke AuthorizedKeysCommand
    # if any parent directory of the script is group/world-writable. NixOS's
    # /nix/store is mode 1775 (group-writable by nixbld), which fails the
    # check. We work around by copying the fetcher script to /etc/ssh/ at
    # activation time — that path has 755 root:root all the way up to /.
    # (Symlinks don't help: stat() follows them.)
    system.activationScripts = mkIf hasFederationUsers {
      federationAuthorizedKeysCommand = ''
        install -m 0755 -o root -g root \
          ${federationKeysFetcher} \
          /etc/ssh/federation-authorized-keys
      '';
    };
    services.openssh = mkIf hasFederationUsers {
      authorizedKeysCommand = "/etc/ssh/federation-authorized-keys %u";
      authorizedKeysCommandUser = "nobody";
    };

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
    ) resolvedUsers);
  };
}
