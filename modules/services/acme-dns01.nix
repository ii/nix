# ii/nix — ACME DNS-01 client (bare service module)
#
# Issues + renews ACME certificates (Let's Encrypt by default) using the
# DNS-01 challenge against a Technitium DNS server's API. Designed for
# wildcard certs (*.foo.example) which DNS-01 supports and HTTP-01 doesn't.
#
# IMPLEMENTATION CHOICE — needs architect blessing:
#   This sketch uses LEGO (https://go-acme.github.io/lego/) as the client
#   driven by a systemd timer. Alternatives weighed:
#     - services.acme (NixOS upstream) — no native Technitium DNS provider;
#       would need a custom dnsProvider script (workable but adds glue)
#     - Caddy with Technitium DNS plugin — heavier; pulls Caddy in even for
#       services that don't need Caddy (Maddy on edges doesn't)
#     - Lego direct — minimal; Technitium provider is supported upstream
#       via the RFC-2136 update protocol with Technitium's TSIG support
#
# Recommend LEGO. Architect to confirm or redirect.
#
# CONSUMER USAGE:
#   imports = [ ii-nix.nixosModules.acme-dns01 ];
#   services.acme-dns01 = {
#     enable = true;
#     email = "hostmaster@ii.coop";
#     domains = [ "*.ii.coop" "ii.coop" ];
#     dnsProvider = "rfc2136";           # talks to Technitium via TSIG
#     credentialFile = config.sops.secrets."acme-dns01-creds".path;
#     certPath = "/var/lib/acme/wildcard-ii-coop";
#   };
#
# The credentialFile is a sops-encrypted env-file with the TSIG key + the
# Technitium endpoint:
#     RFC2136_NAMESERVER=127.0.0.1:53
#     RFC2136_TSIG_ALGORITHM=hmac-sha256
#     RFC2136_TSIG_KEY=ii-federation-acme
#     RFC2136_TSIG_SECRET=<base64-secret>
#
# ARCHITECT TODO: bless lego choice + dnsProvider naming; decide whether to
# wrap as a federation-level "certs" interface in modules/certs.nix (yes,
# per Q1 — see that module). This module stays bare and consumed by
# modules/certs.nix.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.acme-dns01;
  iiLib = (import ../../lib { inherit (pkgs) lib; });
in {
  options.services.acme-dns01 = with lib; {
    enable = mkEnableOption "ACME DNS-01 client (lego-based, Technitium target)";

    email = mkOption {
      type = types.str;
      example = "hostmaster@ii.coop";
      description = "ACME account contact email (Let's Encrypt registration).";
    };

    domains = mkOption {
      type = types.listOf types.str;
      example = [ "*.ii.coop" "ii.coop" ];
      description = "Domains to issue a cert for (wildcards supported).";
    };

    dnsProvider = mkOption {
      type = types.str;
      default = "rfc2136";
      description = ''
        Lego DNS provider name. Default 'rfc2136' uses RFC-2136 dynamic
        update protocol, which Technitium supports with TSIG.
      '';
    };

    credentialFile = mkOption {
      type = types.path;
      description = ''
        Path to a sops-managed env-file containing the DNS provider
        credentials. Format depends on dnsProvider; for rfc2136:
          RFC2136_NAMESERVER, RFC2136_TSIG_ALGORITHM,
          RFC2136_TSIG_KEY, RFC2136_TSIG_SECRET
      '';
    };

    certPath = mkOption {
      type = types.str;
      default = "/var/lib/acme/wildcard";
      description = "Where to write the issued cert + key.";
    };

    renewalInterval = mkOption {
      type = types.str;
      default = "weekly";
      description = ''
        systemd OnCalendar expression for renewal checks. Lego will only
        renew when within 30 days of expiry; check frequency is cheap.
      '';
    };

    acmeServer = mkOption {
      type = types.str;
      default = "https://acme-v02.api.letsencrypt.org/directory";
      description = "ACME directory URL.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.acme-dns01 = {
      description = "ACME DNS-01 certificate issuance (lego)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        # Lego respects standard env vars
      };

      serviceConfig = iiLib.hardening.staticBinary // {
        Type = "oneshot";
        ExecStart =
          let
            args = lib.escapeShellArgs ([
              "--accept-tos"
              "--email" cfg.email
              "--server" cfg.acmeServer
              "--dns" cfg.dnsProvider
              "--path" cfg.certPath
            ] ++ (lib.concatMap (d: [ "--domains" d ]) cfg.domains));
          in
          "${pkgs.lego}/bin/lego ${args} run";

        # Override hardening: needs network egress + cert file write.
        # StateDirectory creates certPath under /var/lib AND chowns it to
        # the dynamic user. Required (not just nice-to-have): without it,
        # systemd's namespace setup fails with status=226/NAMESPACE because
        # ReadWritePaths can't bind-mount a directory that doesn't exist.
        StateDirectory =
          assert lib.hasPrefix "/var/lib/" cfg.certPath;
          lib.removePrefix "/var/lib/" cfg.certPath;
        ReadWritePaths = [ cfg.certPath ];
        EnvironmentFile = cfg.credentialFile;
      };
    };

    systemd.timers.acme-dns01 = {
      description = "ACME DNS-01 renewal check";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.renewalInterval;
        # Also check 1 minute after boot — catches the case where the box
        # was down through its scheduled renewal window.
        OnStartupSec = "1m";
        Persistent = true;
        RandomizedDelaySec = "1h";
      };
    };
  };
}
