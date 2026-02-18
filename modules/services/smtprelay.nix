# smtprelay.nix — SMTP relay service (Grafana smtprelay)
#
# Forwards outbound mail from local services to upstream SMTP (e.g. Mailgun).
# Based on proven Loom pattern:
#   - Uses script block (not ExecStart) for correct env var propagation
#   - Reads credentials from file, splits user:password
#   - Sets REMOTE_PASS as env var (smtprelay reads it automatically)
#   - Correct flags: -remote_host, -remote_auth plain, -remote_user
#
# Usage:
#   ii.services.smtprelay = {
#     enable = true;
#     hostname = "ii.dev";
#     remoteHost = "smtp.mailgun.org:587";
#     remoteAuthFile = config.sops.secrets.smtp-relay-auth.path;
#   };

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.ii.services.smtprelay;
in
{
  options.ii.services.smtprelay = {
    enable = mkEnableOption "SMTP relay via Grafana smtprelay";

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1:2525";
      description = "Address:port to listen on (localhost only for security)";
    };

    remoteHost = mkOption {
      type = types.str;
      description = "Upstream SMTP server (e.g. smtp.mailgun.org:587)";
      example = "smtp.mailgun.org:587";
    };

    remoteAuthFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Path to file containing SMTP auth in format: username:password
        If null, no authentication is used.
      '';
    };

    hostname = mkOption {
      type = types.str;
      default = "localhost.localdomain";
      description = "SMTP EHLO hostname";
    };

    remoteSender = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Rewrite envelope sender to this address";
    };

    allowedSenders = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Allowed sender patterns (regex)";
    };

    allowedRecipients = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Allowed recipient patterns (regex)";
    };

    logLevel = mkOption {
      type = types.enum [ "debug" "info" "warn" "error" ];
      default = "info";
      description = "Log level";
    };

    metricsListen = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Metrics endpoint address:port (null = default :8080)";
    };

    useTLS = mkOption {
      type = types.bool;
      default = true;
      description = "Use STARTTLS for upstream connection";
    };
  };

  config = mkIf cfg.enable {
    users.users.smtprelay = {
      isSystemUser = true;
      group = "smtprelay";
      description = "SMTP Relay service user";
    };
    users.groups.smtprelay = {};

    systemd.services.ii-smtprelay = {
      description = "SMTP Relay Service (ii)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        User = "smtprelay";
        Group = "smtprelay";
        Restart = "always";
        RestartSec = "5s";

        # Hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
      };

      # Script block — critical for REMOTE_PASS env var to propagate
      script = ''
        set -euo pipefail

        ARGS=()
        ARGS+=("-listen" "${cfg.listenAddress}")
        ARGS+=("-hostname" "${cfg.hostname}")
        ARGS+=("-remote_host" "${cfg.remoteHost}")
        ARGS+=("-log_level" "${cfg.logLevel}")

        ${optionalString (cfg.remoteAuthFile != null) ''
          REMOTE_CREDS=$(cat ${cfg.remoteAuthFile})
          REMOTE_USER="''${REMOTE_CREDS%%:*}"
          export REMOTE_PASS="''${REMOTE_CREDS#*:}"
          ARGS+=("-remote_auth" "plain")
          ARGS+=("-remote_user" "$REMOTE_USER")
        ''}

        ${optionalString (cfg.allowedSenders != []) ''
          ARGS+=("-allowed_sender" "${concatStringsSep "," cfg.allowedSenders}")
        ''}

        ${optionalString (cfg.allowedRecipients != []) ''
          ARGS+=("-allowed_recipients" "${concatStringsSep "," cfg.allowedRecipients}")
        ''}

        ${optionalString (cfg.remoteSender != null) ''
          ARGS+=("-remote_sender" "${cfg.remoteSender}")
        ''}

        ${optionalString (cfg.metricsListen != null) ''
          ARGS+=("-metrics_listen" "${cfg.metricsListen}")
        ''}

        exec ${pkgs.smtprelay}/bin/smtprelay "''${ARGS[@]}"
      '';
    };
  };
}
