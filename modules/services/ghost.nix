# ghost.nix — Ghost blog engine via OCI container
#
# IMPORTANT: pkgs.ghost in nixpkgs is EntySec/ghost (Android exploitation tool),
# NOT the Ghost blog engine. Ghost CMS is not packaged in nixpkgs.
#
# This module runs Ghost via Podman (OCI container) as a systemd service.
# Each Ghost instance runs as a domain user, with data in their home dir.
#
# Usage:
#   ii.services.ghost.instances = {
#     "abcs" = {
#       domain = "abcs.news";
#       port = 2368;
#     };
#   };
#
# Reads from config.ii.generated to wire up the right user/group.

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.ii.services.ghost;
in
{
  options.ii.services.ghost = {
    enable = mkEnableOption "Ghost blog engine via OCI containers";

    image = mkOption {
      type = types.str;
      default = "docker.io/ghost:5-alpine";
      description = "Ghost OCI image to use";
    };

    instances = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          domain = mkOption {
            type = types.str;
            description = "Public domain for this Ghost instance (e.g. abcs.news)";
          };

          port = mkOption {
            type = types.port;
            default = 2368;
            description = "Port for Ghost to listen on (localhost only)";
          };

          dataDir = mkOption {
            type = types.nullOr types.path;
            default = null;
            description = "Data directory. Defaults to /var/lib/<instance>/ghost";
          };

          mail = {
            from = mkOption {
              type = types.str;
              default = "";
              description = "From address for emails. Defaults to noreply@<domain>";
            };

            smtpHost = mkOption {
              type = types.str;
              default = "127.0.0.1";
              description = "SMTP host (use local smtprelay)";
            };

            smtpPort = mkOption {
              type = types.port;
              default = 2525;
              description = "SMTP port on the relay";
            };
          };

          extraEnv = mkOption {
            type = types.attrsOf types.str;
            default = {};
            description = "Additional environment variables for the Ghost container";
          };
        };
      });
      default = {};
      description = "Ghost blog instances, keyed by the ii.users name (domain user)";
    };
  };

  config = mkIf cfg.enable {
    # Ensure podman is available
    virtualisation.podman = {
      enable = true;
      dockerCompat = false;
    };

    # Generate a systemd service for each Ghost instance
    systemd.services = mapAttrs' (name: instanceCfg:
      let
        dataDir = if instanceCfg.dataDir != null
          then instanceCfg.dataDir
          else "/var/lib/${name}/ghost";
        fromAddr = if instanceCfg.mail.from != ""
          then instanceCfg.mail.from
          else "noreply@${instanceCfg.domain}";
        url = "https://${instanceCfg.domain}";
      in
      nameValuePair "ghost-${name}" {
        description = "Ghost blog (${instanceCfg.domain})";
        after = [ "network-online.target" "podman.socket" ];
        wants = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];

        preStart = ''
          mkdir -p ${dataDir}/content
          # Ensure the data dir is owned by Ghost's internal UID (1000 in the container)
          # We bind-mount, so host ownership matters
        '';

        serviceConfig = {
          Type = "simple";
          Restart = "on-failure";
          RestartSec = "10s";
          TimeoutStartSec = "120s";
        };

        script = ''
          exec ${pkgs.podman}/bin/podman run \
            --rm \
            --name ghost-${name} \
            --network host \
            --user 1000:1000 \
            -v ${dataDir}/content:/var/lib/ghost/content:Z \
            -e url=${url} \
            -e server__host=127.0.0.1 \
            -e server__port=${toString instanceCfg.port} \
            -e database__client=sqlite3 \
            -e database__connection__filename=/var/lib/ghost/content/data/ghost.db \
            -e database__useNullAsDefault=true \
            -e mail__transport=SMTP \
            -e mail__from="${fromAddr}" \
            -e mail__options__host=${instanceCfg.mail.smtpHost} \
            -e mail__options__port=${toString instanceCfg.mail.smtpPort} \
            -e mail__options__secure=false \
            -e logging__level=info \
            -e logging__transports='["stdout"]' \
            -e privacy__useUpdateCheck=false \
            -e privacy__useGravatar=false \
            -e NODE_ENV=production \
            ${concatStringsSep " \\\n            " (mapAttrsToList (k: v: "-e ${k}=${v}") instanceCfg.extraEnv)} \
            ${cfg.image}
        '';
      }
    ) cfg.instances;

    # Create data directories
    systemd.tmpfiles.rules = concatLists (mapAttrsToList (name: instanceCfg:
      let
        dataDir = if instanceCfg.dataDir != null
          then instanceCfg.dataDir
          else "/var/lib/${name}/ghost";
      in [
        "d ${dataDir} 0750 1000 1000 -"
        "d ${dataDir}/content 0750 1000 1000 -"
        "d ${dataDir}/content/data 0750 1000 1000 -"
        "d ${dataDir}/content/images 0750 1000 1000 -"
        "d ${dataDir}/content/themes 0750 1000 1000 -"
      ]
    ) cfg.instances);
  };
}
