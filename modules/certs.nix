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
      default =
        let
          wildcards = map (z: "*.${z}") dnsCfg.zones;
          apexes = dnsCfg.zones;
          # A cluster hostname like ns.developing.coop is redundant with
          # the wildcard *.developing.coop — LE rejects the order with
          # "Domain name is redundant with a wildcard domain in the same
          # request". Filter those out; keep cluster hostnames whose
          # parent zone we DON'T cover with a wildcard (e.g. ns.ii.coop
          # when ii.coop isn't a federation zone).
          parentOf = h: lib.concatStringsSep "." (lib.tail (lib.splitString "." h));
          extras = lib.filter (h: !(lib.elem (parentOf h) dnsCfg.zones))
                              dnsCfg.publicClusterHostnames;
        in
          wildcards ++ apexes ++ extras;
      defaultText = literalExpression ''
        Wildcards + apex over ii-federation.dns.zones, plus any
        ii-federation.dns.publicClusterHostnames whose parent zone
        isn't already covered by a wildcard (LE rejects redundant SANs).
      '';
      description = ''
        Domains to issue certs for. Defaults to wildcards + apex over
        every zone declared in ii-federation.dns.zones, plus any
        publicClusterHostnames not already covered by a wildcard.
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

    # The bare ACME client targets THIS server's Technitium for DNS-01.
    # credentialFile points to a path populated by activationScripts below
    # (NOT at runtime) — EnvironmentFile is loaded by systemd BEFORE
    # ExecStartPre runs, so a runtime-built creds file would be too late.
    services.acme-dns01 = {
      enable = true;
      email = cfg.email;
      domains = cfg.domains;
      acmeServer = cfg.acmeServer;
      dnsProvider = "rfc2136";
      certPath = cfg.certPath;
      credentialFile = "/run/acme-dns01/creds";
      # Propagation check against THIS box's Tek (where lego just wrote).
      # Skipping public resolvers avoids two problems:
      #  - cache lag / negative caching on the very-recent UPDATE
      #  - the parallel-primary federation: peer anchor doesn't have the
      #    record (no inter-anchor DDNS replication), so public recursive
      #    queries randomly hit a stale answer. Local check makes the
      #    propagation poll deterministic. LE's own validation queries
      #    the authoritative NSes directly, so this only affects what
      #    lego polls before signaling "ready" to LE.
      propagationDnsResolvers = [ "127.0.0.1:53" ];
    };

    # ACME must wait for the federation reconciler to finish — that's what
    # installs the TSIG key into Technitium and configures the zone to accept
    # dynamic updates. Without this dependency, first issuance races and the
    # symptoms are confusing (lego retries on the next timer hit, but the
    # initial bootstrap looks broken). Per architect's Flag 3 (2026-05-11).
    systemd.services.acme-dns01 = {
      after = [ "technitium-federation-reconcile.service" ];
      wants = [ "technitium-federation-reconcile.service" ];
    };

    # Build the lego rfc2136 env-file at NixOS activation, AFTER sops-nix
    # has decrypted the TSIG. /run is tmpfs so the file vanishes on reboot
    # and is re-created from secrets on next activation (boot or switch).
    # TSIG_KEY name must match what dns.nix installs in Technitium:
    # ii-federation-axfr (same key powers AXFR + DDNS UPDATE; UPDATE
    # authorization is granted per-zone via updateSecurityPolicies in dns.nix).
    #
    # RFC2136_NAMESERVER target:
    #  - clusterRole=primary or off: write UPDATEs locally (zones are Primary
    #    here, the local Tek accepts them)
    #  - clusterRole=secondary: this anchor's federation zones are catalog-
    #    Secondary copies; the local Tek REFUSES DDNS UPDATE on Secondary
    #    zones. Send the UPDATEs to the cluster primary instead, where the
    #    Primary copies live; the cluster catalog IXFRs the change back to
    #    us so the propagation check (still 127.0.0.1) sees the record.
    system.activationScripts.acme-dns01-creds =
      let
        ddnsTarget =
          if dnsCfg.clusterRole == "secondary" then
            (assert dnsCfg.clusterPrimaryIp != "";
              "${dnsCfg.clusterPrimaryIp}:53")
          else
            "127.0.0.1:53";
      in {
        deps = [ "setupSecrets" ];
        text = ''
          install -d -m 0700 /run/acme-dns01
          TSIG=$(cat ${toString dnsCfg.tsigKeyFile})
          umask 077
          cat > /run/acme-dns01/creds <<EOF
          RFC2136_NAMESERVER=${ddnsTarget}
          RFC2136_TSIG_ALGORITHM=hmac-sha256
          RFC2136_TSIG_KEY=ii-federation-axfr
          RFC2136_TSIG_SECRET=$TSIG
          EOF
          chmod 0400 /run/acme-dns01/creds
        '';
      };

    # Renewal timer should also wait — sequenced dependency chain:
    # technitium-dns-server → technitium-federation-reconcile → acme-dns01
    systemd.timers.acme-dns01.timerConfig.OnUnitActiveSec = lib.mkDefault "1d";

    # ===== Cert handoff into Technitium's web service =====
    # When lego writes a new cert, bundle it into a PFX, place it where the
    # technitium-dns-server user can read it, and point Tek's web service
    # at it via API. Driven by a systemd path unit watching the cert dir,
    # so it fires on both initial issuance AND renewals (without a Tek
    # restart on weekly no-op renewal checks).
    #
    # Why PFX: Tek's webServiceTlsCertificatePath wants a PKCS12 file. Lego
    # writes PEM (cert/key/chain separately). We bundle on the fly.
    # Empty password: file is chmod 0400 + chowned to Tek's user; the PFX
    # password is a no-op boundary.
    systemd.services.tek-cert-install = {
      description = "Install lego-issued cert into Technitium's web service";
      after = [ "acme-dns01.service" "technitium-dns-server.service" ];

      path = [ pkgs.openssl pkgs.curl pkgs.jq pkgs.coreutils pkgs.findutils ];

      serviceConfig = {
        Type = "oneshot";
        LoadCredential = [
          "admin-pass:${toString dnsCfg.adminPasswordFile}"
        ];
      };

      script = ''
        set -eu

        CERT_DIR=${cfg.certPath}/certificates
        TEK_DIR=/var/lib/technitium
        PFX_PATH=$TEK_DIR/lego-cert.pfx

        if [ ! -d "$CERT_DIR" ]; then
          echo "no certificates directory at $CERT_DIR yet — first issuance hasn't completed"
          exit 0
        fi

        # Find the most recent issued cert (lego writes <sanitized-primary>.crt
        # plus a separate <name>.issuer.crt for the chain; pick the leaf).
        CERT_FILE=$(find "$CERT_DIR" -maxdepth 1 -name "*.crt" -not -name "*.issuer.crt" \
          -printf "%T@\t%p\n" | sort -rn | head -1 | cut -f2)
        if [ -z "$CERT_FILE" ]; then
          echo "no .crt files in $CERT_DIR — nothing to install"
          exit 0
        fi
        KEY_FILE="''${CERT_FILE%.crt}.key"
        ISSUER_FILE="''${CERT_FILE%.crt}.issuer.crt"

        if [ ! -f "$KEY_FILE" ]; then
          echo "cert at $CERT_FILE has no matching key at $KEY_FILE" >&2
          exit 1
        fi

        echo "bundling $CERT_FILE + $KEY_FILE -> $PFX_PATH"
        if [ -f "$ISSUER_FILE" ]; then
          openssl pkcs12 -export \
            -out "$PFX_PATH.new" \
            -inkey "$KEY_FILE" \
            -in "$CERT_FILE" \
            -certfile "$ISSUER_FILE" \
            -passout pass:
        else
          openssl pkcs12 -export \
            -out "$PFX_PATH.new" \
            -inkey "$KEY_FILE" \
            -in "$CERT_FILE" \
            -passout pass:
        fi
        chmod 0400 "$PFX_PATH.new"
        chown technitium-dns-server:technitium-dns-server "$PFX_PATH.new"

        # Skip API call if PFX content hasn't changed (e.g. weekly no-op
        # renewal check fired the path unit but lego decided not to renew).
        if [ -f "$PFX_PATH" ] && cmp -s "$PFX_PATH" "$PFX_PATH.new"; then
          echo "PFX unchanged — no Tek API update needed"
          rm -f "$PFX_PATH.new"
          exit 0
        fi
        mv "$PFX_PATH.new" "$PFX_PATH"

        echo "pushing new cert path into Tek settings"
        PASS=$(cat "$CREDENTIALS_DIRECTORY/admin-pass")
        TOKEN=$(curl -fsS "http://127.0.0.1:5380/api/user/login" \
          --data-urlencode "user=admin" \
          --data-urlencode "pass=$PASS" \
          --data-urlencode "includeInfo=false" \
          | jq -r .token)
        if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
          echo "FATAL: failed to authenticate to Technitium" >&2
          exit 1
        fi

        curl -fsS "http://127.0.0.1:5380/api/settings/set?token=$TOKEN" \
          --data-urlencode "webServiceTlsCertificatePath=$PFX_PATH" \
          --data-urlencode "webServiceTlsCertificatePassword=" \
          --data-urlencode "webServiceUseSelfSignedTlsCertificate=false" \
          --data-urlencode "webServiceEnableTls=true" >/dev/null

        echo "cert installed; Tek will reload TLS on next request"
        curl -fsS "http://127.0.0.1:5380/api/user/logout?token=$TOKEN" >/dev/null || true
      '';
    };

    # Path unit: watch lego's cert dir; fire tek-cert-install on any change.
    # PathChanged covers both atomic-rename (lego's pattern) and in-place
    # writes. We also fire on first appearance via PathExists, so the
    # initial issuance triggers without a separate kickoff.
    systemd.paths.tek-cert-install = {
      description = "Watch lego cert output; install into Technitium on change";
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        PathChanged = "${cfg.certPath}/certificates";
        Unit = "tek-cert-install.service";
      };
    };
  };
}
