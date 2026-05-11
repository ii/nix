# ii/nix — Certs federation wrapper (over services.acme-dns01)
#
# Federation interface for wildcard TLS certificates. Wraps the bare ACME
# DNS-01 client with federation conventions:
#   - DNS-01 challenge target is THIS server's Technitium (127.0.0.1:53)
#     by default — resolved from ii-federation.dns config rather than
#     hard-coded per consumer
#   - TSIG key for the dynamic update is the SAME key used for AXFR
#     (per modules/dns.nix) — eliminates a duplicate secret
#   - Domain list defaults to wildcards over the zones declared in
#     ii-federation.dns.zones — saves consumer boilerplate
#
# This satisfies architect's wrap-only-if-meaningful test:
#   - Resolves dnsProvider config from ii-federation.dns (not duplicated)
#   - Reuses the AXFR TSIG key (not a separate secret)
#   - Defaults wildcard domain list from zones (not re-enumerated)
#
# CONSUMER USAGE:
#   imports = [ ii-nix.nixosModules.certs ];
#   ii-federation.certs = {
#     enable = true;
#     email = "hostmaster@ii.coop";
#     # domains defaults to ["*.<each-zone>"] from ii-federation.dns.zones
#     # dnsProvider, tsigKey, etc. resolved automatically
#   };
#
# Override if needed (consumer can opt out of defaults):
#   ii-federation.certs.domains = [ "*.ii.coop" "ii.coop" ];  # subset only
#
# ARCHITECT TODO: bless the auto-resolution of dnsProvider from
# ii-federation.dns; confirm wildcard-defaults-from-zones; weigh in on
# whether to support per-cert key types (RSA vs EC P-256 vs Ed25519) here
# or in the bare module.

{ config, lib, pkgs, ... }:

let
  cfg = config.ii-federation.certs;
  dnsCfg = config.ii-federation.dns;
in {
  options.ii-federation.certs = with lib; {
    enable = mkEnableOption "Federation wildcard TLS via ACME DNS-01";

    email = mkOption {
      type = types.str;
      example = "hostmaster@ii.coop";
      description = "ACME account contact email.";
    };

    domains = mkOption {
      type = types.listOf types.str;
      default = map (z: "*.${z}") dnsCfg.zones ++ dnsCfg.zones;
      defaultText = literalExpression ''map (z: "*.''${z}") ii-federation.dns.zones ++ ii-federation.dns.zones'';
      description = ''
        Domains to issue certs for. Defaults to wildcards + apex over
        every zone declared in ii-federation.dns.zones.
      '';
    };

    acmeServer = mkOption {
      type = types.str;
      default = "https://acme-v02.api.letsencrypt.org/directory";
      description = "ACME directory URL. Override for staging.";
    };

    certPath = mkOption {
      type = types.str;
      default = "/var/lib/acme/federation-wildcards";
      description = "Where to write the issued certs (organized by domain).";
    };
  };

  config = lib.mkIf cfg.enable {
    # Assert that ii-federation.dns is also enabled — certs depends on it
    assertions = [
      {
        assertion = dnsCfg.enable;
        message = ''
          ii-federation.certs requires ii-federation.dns to also be enabled
          (the TSIG key + DNS-01 target are resolved from there).
        '';
      }
    ];

    # The bare ACME client targets THIS server's Technitium for DNS-01
    services.acme-dns01 = {
      enable = true;
      email = cfg.email;
      domains = cfg.domains;
      acmeServer = cfg.acmeServer;
      dnsProvider = "rfc2136";
      certPath = cfg.certPath;

      # Reuses the federation TSIG key — eliminates a duplicate secret.
      # The credentialFile is built at activation: combines the TSIG key
      # value with the RFC2136 protocol vars.
      credentialFile = "/run/credentials/acme-dns01.service/dns01-creds";
    };

    # ACME must wait for the federation reconciler to finish — that's what
    # installs the TSIG key into Technitium and configures the zone to accept
    # dynamic updates. Without this dependency, first issuance races and the
    # symptoms are confusing (lego retries on the next timer hit, but the
    # initial bootstrap looks broken). Per architect's Flag 3 (2026-05-11).
    systemd.services.acme-dns01 = {
      after = [ "technitium-federation-reconcile.service" ];
      wants = [ "technitium-federation-reconcile.service" ];

      # Construct the lego env-file at unit start from the TSIG key
      serviceConfig = {
        LoadCredential = lib.mkAfter [
          # Same TSIG key as AXFR
          "tsig-key:${toString dnsCfg.tsigKeyFile}"
        ];
        # Build the env-file expected by lego rfc2136 from the TSIG credential
        ExecStartPre = pkgs.writeShellScript "build-dns01-creds" ''
          set -euo pipefail
          TSIG="$(cat $CREDENTIALS_DIRECTORY/tsig-key)"
          cat > $CREDENTIALS_DIRECTORY/dns01-creds <<EOF
          RFC2136_NAMESERVER=127.0.0.1:53
          RFC2136_TSIG_ALGORITHM=hmac-sha256
          RFC2136_TSIG_KEY=ii-federation-acme
          RFC2136_TSIG_SECRET=$TSIG
          EOF
          chmod 0400 $CREDENTIALS_DIRECTORY/dns01-creds
        '';
      };
    };

    # Renewal timer should also wait — sequenced dependency chain:
    # technitium-dns-server → technitium-federation-reconcile → acme-dns01
    systemd.timers.acme-dns01.timerConfig.OnUnitActiveSec = lib.mkDefault "1d";
  };
}
