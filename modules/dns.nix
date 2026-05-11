# ii/nix — DNS federation wrapper (over services.technitium)
#
# Federation interface for authoritative DNS. Configures Technitium (the
# concrete impl) with federation conventions:
#   - Zone list managed declaratively (zones come from this config, not the
#     Technitium admin UI)
#   - TSIG keys sourced from sops secrets
#   - ACLs encoding which hosts can AXFR (the other federation NS)
#   - Glue records derived from federation-known IPs
#
# This is the "abstraction layer above bare nixpkgs" architect blessed in
# the Q1 wrap-only-if-meaningful test. Wrapping is justified here because:
#   - The zone-list pattern is federation policy (every edge serves every
#     federation zone, parallel-primary)
#   - TSIG-from-sops is non-trivial wiring (multiple secrets, multiple
#     consumers — see modules/certs.nix's lego config that uses the same
#     TSIG key for DNS-01 challenges)
#   - The AXFR ACL encodes the federation NS topology (currently 2 boxes;
#     could grow)
#
# CONSUMER USAGE:
#   imports = [ ii-nix.nixosModules.dns ];
#   ii-federation.dns = {
#     enable = true;
#     primaryHostname = "ns.ii.coop";   # this server's hostname
#     primaryIP = "129.158.209.28";     # for SOA-derived defaults
#     peerNameservers = [
#       { hostname = "ns.developing.coop"; ipv4 = "163.192.206.22"; }
#     ];
#     zones = [ "ii.coop" "ii.dev" "ii.nz" "ii.africa" "developing.coop" ];
#     tsigKeyFile = config.sops.secrets."dns-axfr-tsig".path;
#     # Per-zone records left to consumer's ii-federation.dns.records or
#     # added post-deploy via Technitium API; zone files NOT inlined here.
#   };
#
# Sets up:
#   services.technitium.enable = true (with our profile)
#   sops.secrets entries for the TSIG keys
#   A post-start systemd ExecStartPost that calls Technitium API to:
#     - Create each declared zone if not present
#     - Set SOA with primaryHostname / peer NS records
#     - Install TSIG key for AXFR
#     - Apply AXFR ACL: only peers in peerNameservers
#
# ARCHITECT-BLESSED: 2026-05-11
#   - API-call-via-systemd-oneshot reconciliation: yes
#   - Idempotent design: every API call tolerates 'already exists' and
#     converges to declared state
#   - Verify-after-apply via GET /api/zones with drift logging
#   - TSIG-based AXFR ACL: yes
# Open for follow-up: per-zone record submodule (apex A, MX, etc.) — left
# for when consumers actually need it; not adding option machinery early.

{ config, lib, pkgs, ... }:

let
  cfg = config.ii-federation.dns;
  iiLib = (import ../lib { inherit (pkgs) lib; });
in {
  options.ii-federation.dns = with lib; {
    enable = mkEnableOption "Federation DNS (Technitium-backed authoritative)";

    primaryHostname = mkOption {
      type = types.str;
      example = "ns.ii.coop";
      description = "This server's NS hostname (announced in SOA).";
    };

    primaryIP = mkOption {
      type = types.str;
      example = "129.158.209.28";
      description = ''
        This server's public IPv4. Used in zone glue records when
        appropriate. (IPv6 is intentionally NOT a federation invariant
        yet — see ii-mgr's runbook for the IPv6 readiness phase.)
      '';
    };

    peerNameservers = mkOption {
      type = types.listOf (types.submodule {
        options = {
          hostname = mkOption { type = types.str; };
          ipv4 = mkOption { type = types.str; };
        };
      });
      default = [ ];
      example = [
        { hostname = "ns.developing.coop"; ipv4 = "163.192.206.22"; }
      ];
      description = ''
        Other federation nameservers. Each zone's NS records include
        primaryHostname + all peer hostnames. Each peer is granted AXFR
        access via the TSIG ACL.
      '';
    };

    zones = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "ii.coop" "ii.dev" "developing.coop" ];
      description = ''
        Authoritative zones this server hosts. Every federation edge
        serves every zone (parallel-primary). Per-zone records are
        managed separately (TBD — likely a per-zone submodule when
        conventions emerge; for now via Technitium API post-deploy).
      '';
    };

    tsigKeyFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing the AXFR TSIG key. Sops-managed
        /run/secrets/ path. Same key is used by modules/certs.nix for
        DNS-01 ACME updates.
      '';
    };

    adminPasswordFile = mkOption {
      type = types.path;
      description = ''
        Path to the Technitium admin password file (passed through to
        services.technitium).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Enable the bare Technitium service with our parameters
    services.technitium = {
      enable = true;
      dnsServerDomain = cfg.primaryHostname;
      adminPasswordFile = cfg.adminPasswordFile;
      openFirewall = true;
    };

    # Federation-level: a post-start API script reconciles Technitium's
    # internal zone state against our declared zones list. Idempotent.
    # Architect-blessed approach (2026-05-11): API-call-via-systemd-oneshot;
    # every step tolerates 'already exists' and converges to declared state.
    systemd.services.technitium-federation-reconcile = {
      description = "Reconcile Technitium zones against federation config";
      after = [ "technitium-dns-server.service" ];
      bindsTo = [ "technitium-dns-server.service" ];
      wantedBy = [ "multi-user.target" ];

      path = [ pkgs.curl pkgs.jq pkgs.coreutils ];

      environment = {
        ZONES = lib.concatStringsSep "\n" cfg.zones;
        PEER_HOSTNAMES = lib.concatStringsSep "\n" (map (p: p.hostname) cfg.peerNameservers);
        PEER_IPS = lib.concatStringsSep "\n" (map (p: p.ipv4) cfg.peerNameservers);
        PRIMARY_HOSTNAME = cfg.primaryHostname;
        PRIMARY_IP = cfg.primaryIP;
        TECHNITIUM_HOST = "http://127.0.0.1:5380";
        TSIG_KEY_NAME = "ii-federation-axfr";
      };

      script = ''
        set -eu

        PASS=$(cat "$CREDENTIALS_DIRECTORY/admin-password")
        TSIG_SECRET=$(cat "$CREDENTIALS_DIRECTORY/tsig-key")

        # ---------- Wait for Technitium API ready (post-start race) ----------
        for i in 1 2 3 4 5 6 7 8 9 10; do
          if curl -fsS "$TECHNITIUM_HOST/" >/dev/null 2>&1; then break; fi
          sleep 2
        done

        # ---------- Authenticate ----------
        TOKEN=$(curl -fsS "$TECHNITIUM_HOST/api/user/login" \
          --data-urlencode "user=admin" \
          --data-urlencode "pass=$PASS" \
          --data-urlencode "includeInfo=false" \
          | jq -r .token)
        if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
          echo "FATAL: failed to authenticate to Technitium" >&2
          exit 1
        fi

        api() {
          local endpoint=$1; shift
          # 409 (conflict / already exists) treated as success — idempotent
          local http_code
          http_code=$(curl -sS -o /tmp/api-resp -w '%{http_code}' \
            "$TECHNITIUM_HOST/api/$endpoint" \
            --data-urlencode "token=$TOKEN" "$@")
          if [ "$http_code" = "200" ] || [ "$http_code" = "409" ]; then
            return 0
          fi
          echo "API call failed: $endpoint (HTTP $http_code)" >&2
          cat /tmp/api-resp >&2
          return 1
        }

        # ---------- Install AXFR TSIG key (federation-shared) ----------
        api settings/tsig/set \
          --data-urlencode "keyName=$TSIG_KEY_NAME" \
          --data-urlencode "sharedSecret=$TSIG_SECRET" \
          --data-urlencode "algorithm=hmac-sha256"

        # ---------- Per-zone reconciliation ----------
        echo "$ZONES" | while IFS= read -r zone; do
          [ -z "$zone" ] && continue
          echo "==> reconciling zone: $zone"

          # Step a: create zone (idempotent — 409 = already exists, OK)
          api zones/create \
            --data-urlencode "zone=$zone" \
            --data-urlencode "type=Primary" || true

          # Step b: SOA via zone options
          api zones/options/set \
            --data-urlencode "zone=$zone" \
            --data-urlencode "primaryNameServer=$PRIMARY_HOSTNAME" \
            --data-urlencode "responsiblePerson=hostmaster.$zone" \
            --data-urlencode "notify=ZoneNameServers" \
            --data-urlencode "zoneTransfer=AllowOnlySpecifiedNameServers" \
            --data-urlencode "zoneTransferTsigKeyNames=$TSIG_KEY_NAME"

          # Step c: NS records — primary + peers
          api zones/records/add \
            --data-urlencode "zone=$zone" \
            --data-urlencode "domain=$zone" \
            --data-urlencode "type=NS" \
            --data-urlencode "nameServer=$PRIMARY_HOSTNAME" \
            --data-urlencode "ttl=3600" || true

          # Peers — read both lists in parallel
          paste <(echo "$PEER_HOSTNAMES") <(echo "$PEER_IPS") | while IFS=$'\t' read -r peer_host peer_ip; do
            [ -z "$peer_host" ] && continue

            api zones/records/add \
              --data-urlencode "zone=$zone" \
              --data-urlencode "domain=$zone" \
              --data-urlencode "type=NS" \
              --data-urlencode "nameServer=$peer_host" \
              --data-urlencode "ttl=3600" || true

            # Glue A for peer hostname if peer is in-zone (e.g., ns.ii.coop in ii.coop)
            # Heuristic: hostname ends with .${zone}
            case "$peer_host" in
              *.$zone)
                api zones/records/add \
                  --data-urlencode "zone=$zone" \
                  --data-urlencode "domain=$peer_host" \
                  --data-urlencode "type=A" \
                  --data-urlencode "ipAddress=$peer_ip" \
                  --data-urlencode "ttl=3600" || true
                ;;
            esac
          done

          # Primary hostname glue A if in-zone
          case "$PRIMARY_HOSTNAME" in
            *.$zone)
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$PRIMARY_HOSTNAME" \
                --data-urlencode "type=A" \
                --data-urlencode "ipAddress=$PRIMARY_IP" \
                --data-urlencode "ttl=3600" || true
              ;;
          esac
        done

        # ---------- Verify-after-apply: GET zones, log drift ----------
        echo "==> verification: listing live zones"
        LIVE_ZONES=$(curl -fsS "$TECHNITIUM_HOST/api/zones/list" \
          --data-urlencode "token=$TOKEN" \
          | jq -r '.response.zones[].name' | sort)
        DECLARED_ZONES=$(echo "$ZONES" | sort)

        MISSING=$(comm -23 <(echo "$DECLARED_ZONES") <(echo "$LIVE_ZONES") || true)
        EXTRA=$(comm -13 <(echo "$DECLARED_ZONES") <(echo "$LIVE_ZONES") || true)

        if [ -n "$MISSING" ]; then
          echo "WARN: declared zones missing from live: $MISSING" >&2
        fi
        if [ -n "$EXTRA" ]; then
          echo "NOTE: live zones not declared in federation config: $EXTRA" >&2
          # Don't fail on extras — could be tenant-onboarding-in-progress
        fi

        # Logout
        api user/logout > /dev/null || true
      '';

      serviceConfig = iiLib.hardening.staticBinary // {
        Type = "oneshot";
        RemainAfterExit = true;
        LoadCredential = [
          "tsig-key:${toString cfg.tsigKeyFile}"
          "admin-password:${toString cfg.adminPasswordFile}"
        ];
      };
    };
  };
}
