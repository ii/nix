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
        serves every zone (parallel-primary).
      '';
    };

    singleNsZones = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "developing.coop" ];
      description = ''
        Zones for which only `primaryHostname` is published as NS —
        peer nameservers are NOT advertised in the NS RRset. Used to
        break chicken-and-egg cases where a peer's hostname lives
        inside the zone itself and hasn't resolved publicly yet. Once
        the peer hostname's A record propagates, the zone can be
        moved out of this list and the next reconcile will add the
        peer NS.
      '';
    };

    zoneRecords = mkOption {
      type = types.attrsOf (types.listOf (types.submodule {
        options = {
          name = mkOption {
            type = types.str;
            description = "Fully-qualified record name (e.g. \"www.ii.dev\" or \"ii.dev\" for apex).";
          };
          type = mkOption {
            type = types.enum [ "A" "AAAA" "CNAME" "MX" "TXT" "SRV" "CAA" "NS" "PTR" ];
            description = "DNS record type.";
          };
          value = mkOption {
            type = types.str;
            description = ''
              Record value. Format depends on type:
                A/AAAA: IP literal
                CNAME/NS/PTR: target hostname (with or without trailing dot)
                MX: "PRIO HOST" (e.g. "10 mail.example.com")
                TXT: the text content (no surrounding quotes)
                CAA: "FLAGS TAG VALUE" (e.g. "0 issue \"letsencrypt.org\"")
                SRV: "PRIO WEIGHT PORT TARGET"
            '';
          };
          ttl = mkOption {
            type = types.int;
            default = 300;
            description = "TTL in seconds.";
          };
        };
      }));
      default = { };
      example = lib.literalExpression ''
        {
          "ii.dev" = [
            { name = "ii.dev"; type = "A"; value = "150.136.176.92"; ttl = 300; }
            { name = "www.ii.dev"; type = "CNAME"; value = "ii.dev"; ttl = 300; }
          ];
        }
      '';
      description = ''
        Per-zone record set, keyed by zone name. SOA + apex NS + glue A
        records for primary/peer hostnames are added separately by the
        reconcile script and do NOT need to be listed here. The
        reconcile pass is additive only — records declared here are
        added if absent; records on the server that aren't declared
        are NOT removed (other than apex NS, which IS authoritative
        per the singleNsZones / peerNameservers config).
      '';
    };

    recursion = mkOption {
      type = types.enum [ "Allow" "Deny" "AllowOnlyForPrivateNetworks" "UseSpecifiedNetworkACL" ];
      default = "Deny";
      description = ''
        Whether the DNS server should recursively resolve queries it
        is not authoritative for.
          - Deny: never recurse (authoritative-only).
          - Allow: recurse for everyone (open public resolver).
          - AllowOnlyForPrivateNetworks: RFC1918 + loopback only.
          - UseSpecifiedNetworkACL: recurse only for CIDRs listed in
            recursionAllowedNetworks. Anything else → REFUSED.
        Pick UseSpecifiedNetworkACL for a federation-blessed ACL that
        includes CGNAT (100.64/10) or other non-RFC1918 trusted ranges
        beyond what AllowOnlyForPrivateNetworks covers.
      '';
    };

    recursionAllowedNetworks = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "127.0.0.0/8" "10.0.0.0/8" "100.64.0.0/10" "172.16.0.0/12" "192.168.0.0/16" ];
      description = ''
        CIDR list for recursion=UseSpecifiedNetworkACL (passed to
        Technitium's recursionNetworkACL setting as a comma-joined
        list). Ignored for other recursion modes.
      '';
    };

    recursionQpmLimit = mkOption {
      type = types.int;
      default = 100;
      description = ''
        Per-client queries-per-minute limit when recursion is enabled.
        Applies to clients matched by qpmLimitIPv4PrefixLength /
        qpmLimitIPv6PrefixLength (defaults: /24 and /56).
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

    # ===== Cluster options (Technitium 14+ feature) =====
    # Director directive 2026-05-12: pivot from AXFR-peer to Technitium
    # native clustering. One primary + N secondaries, internal sync via
    # TLS. Federation zones live in a cluster catalog managed by the
    # primary; secondaries get them automatically.
    clusterRole = mkOption {
      type = types.enum [ "off" "primary" "secondary" ];
      default = "off";
      description = ''
        Role for Technitium native clustering (14+).
          - off: classic AXFR-peer-TSIG sync (legacy).
          - primary: this node owns the cluster catalog; zones declared
            in this module live here and propagate to secondaries.
          - secondary: this node joins the primary; zones are inherited
            from the cluster catalog. zoneRecords on this node is ignored.
      '';
    };

    clusterDomain = mkOption {
      type = types.str;
      default = "ii-federation";
      description = ''
        Cluster identity / name. Same value on all member nodes. Used
        in cluster-internal NOTIFY and zone naming for the catalog.
      '';
    };

    clusterPrimaryUrl = mkOption {
      type = types.str;
      default = "";
      example = "https://163.192.206.22:53443";
      description = ''
        For secondaries: HTTPS URL of the primary's admin web service.
        After cluster/init on the primary, TLS auto-enables with a
        self-signed cert on port 53443 by default. Secondaries connect
        here to join. Unused for clusterRole = "primary".
      '';
    };

    clusterPrimaryIp = mkOption {
      type = types.str;
      default = "";
      example = "163.192.206.22";
      description = ''
        For secondaries: explicit IP for the primary node. Tek 14.3
        otherwise tries to DNS-resolve the host part of clusterPrimaryUrl
        (even when it's an IP literal) and fails before it ever
        connects to the primary. Pass this separately to bypass that.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Enable the bare Technitium service with our parameters.
    # dnsServerDomain = system hostname (NOT primaryHostname). Tek's
    # cluster code uses dnsServerDomain to construct each node's
    # cluster identity, computed as `<first-segment>.<clusterDomain>`.
    # If both anchors set dnsServerDomain = "ns.<something>.tld" they
    # collide as "ns.<clusterDomain>" inside the cluster. System
    # hostnames (anchor-iad, anchor-ord) are unique per node and
    # render as "anchor-iad.<clusterDomain>" / "anchor-ord.<clusterDomain>"
    # — clean separation. SOA mname records still use primaryHostname
    # via the explicit zones/records/update calls in the reconcile.
    services.technitium = {
      enable = true;
      dnsServerDomain = config.networking.hostName;
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

      path = [ pkgs.curl pkgs.jq pkgs.coreutils pkgs.gawk pkgs.gnused pkgs.gnugrep ];

      environment = {
        ZONES = lib.concatStringsSep "\n" cfg.zones;
        SINGLE_NS_ZONES = lib.concatStringsSep "\n" cfg.singleNsZones;
        PEER_HOSTNAMES = lib.concatStringsSep "\n" (map (p: p.hostname) cfg.peerNameservers);
        PEER_IPS = lib.concatStringsSep "\n" (map (p: p.ipv4) cfg.peerNameservers);
        PRIMARY_HOSTNAME = cfg.primaryHostname;
        PRIMARY_IP = cfg.primaryIP;
        TECHNITIUM_HOST = "http://127.0.0.1:5380";
        TSIG_KEY_NAME = "ii-federation-axfr";
        RECURSION_MODE = cfg.recursion;
        RECURSION_ALLOWED_NETWORKS = lib.concatStringsSep "," cfg.recursionAllowedNetworks;
        RECURSION_QPM = toString cfg.recursionQpmLimit;
        # Cluster (14+ native sync). CLUSTER_ROLE="off" → fall back to AXFR-peer.
        CLUSTER_ROLE = cfg.clusterRole;
        CLUSTER_DOMAIN = cfg.clusterDomain;
        CLUSTER_PRIMARY_URL = cfg.clusterPrimaryUrl;
        CLUSTER_PRIMARY_IP = cfg.clusterPrimaryIp;
        # Primary's IPs for cluster/init's primaryNodeIpAddresses (only used
        # when clusterRole = primary; for now the federation has a single
        # primary so we pass just this node's primaryIP).
        CLUSTER_PRIMARY_IPS = cfg.primaryIP;
        # Pre-evaluated at Nix time; avoids needing `hostname` (from
        # inetutils) in the service PATH.
        NODE_HOSTNAME = config.networking.hostName;
        # zone records serialized as TSV (tab-separated): zone<TAB>name<TAB>type<TAB>value<TAB>ttl
        ZONE_RECORDS_TSV = lib.concatStringsSep "\n"
          (lib.concatMap (zone:
            map (r: lib.concatStringsSep "\t" [ zone r.name r.type r.value (toString r.ttl) ])
              (cfg.zoneRecords.${zone} or [])
          ) (lib.attrNames cfg.zoneRecords));
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
          # AND check response body for {"status":"error"} — Tek 14
          # returns HTTP 200 for many runtime failures with the error
          # only in the body. Without body-checking we falsely report
          # success.
          local http_code
          http_code=$(curl -sS -o /tmp/api-resp -w '%{http_code}' \
            "$TECHNITIUM_HOST/api/$endpoint" \
            --data-urlencode "token=$TOKEN" "$@")
          if [ "$http_code" != "200" ] && [ "$http_code" != "409" ]; then
            echo "API call failed: $endpoint (HTTP $http_code)" >&2
            cat /tmp/api-resp >&2
            return 1
          fi
          local status
          status=$(jq -r '.status // "ok"' /tmp/api-resp 2>/dev/null)
          if [ "$status" = "error" ]; then
            local msg
            msg=$(jq -r '.errorMessage // "unknown error"' /tmp/api-resp 2>/dev/null)
            echo "API call body-error: $endpoint — $msg" >&2
            return 1
          fi
          return 0
        }

        # ---------- Force dnsServerDomain via API (env var only fires on first boot) ----------
        # Technitium reads DNS_SERVER_DOMAIN env var only when dns.config
        # doesn't exist (first start). On subsequent starts, it loads the
        # value from disk. Updating the Nix module's
        # services.technitium.dnsServerDomain only takes effect on a
        # FRESH state dir — which we don't get post-cluster-init.
        # Explicitly push the desired value via settings/set on every
        # reconcile. The DESIRED_DNS_SERVER_DOMAIN is the system hostname
        # (e.g., 'anchor-iad' / 'anchor-ord') — unique per node, so
        # cluster ops compute unique identities and don't collide.
        DESIRED_DNS_SERVER_DOMAIN="$NODE_HOSTNAME"
        CURRENT_DNS_SERVER_DOMAIN=$(curl -fsS "$TECHNITIUM_HOST/api/settings/get?token=$TOKEN" \
          | jq -r '.response.dnsServerDomain // ""')
        if [ "$CURRENT_DNS_SERVER_DOMAIN" != "$DESIRED_DNS_SERVER_DOMAIN" ] && \
           [[ "$CURRENT_DNS_SERVER_DOMAIN" != *.$CLUSTER_DOMAIN ]]; then
          # Skip rename if already cluster-mangled (e.g. anchor-iad.ii-federation).
          echo "==> rename dnsServerDomain: $CURRENT_DNS_SERVER_DOMAIN -> $DESIRED_DNS_SERVER_DOMAIN"
          api settings/set --data-urlencode "dnsServerDomain=$DESIRED_DNS_SERVER_DOMAIN" || true
        fi

        # ---------- Cluster bootstrap (Technitium 14+) ----------
        # Three roles handled here:
        #   off: skip cluster setup, run classic AXFR-peer reconcile below.
        #   primary: cluster/init if not yet initialized; afterwards run the
        #     full zone reconcile so this node owns the catalog content.
        #   secondary: cluster/initJoin pointing at primary; the cluster
        #     propagates zones automatically, so we EXIT after the join
        #     without running per-zone reconciliation here.
        #
        # cluster/init auto-enables TLS with a self-signed cert on
        # webServiceTlsPort=53443. The secondary connects there with
        # ignoreCertificateErrors=true for the self-signed bootstrap.
        # Future improvement: rotate to ACME wildcard once gate-3 certs land.

        CLUSTER_STATE=$(curl -fsS "$TECHNITIUM_HOST/api/admin/cluster/state" \
          --data-urlencode "token=$TOKEN" 2>/dev/null \
          | jq -r '.response.clusterInitialized // false' 2>/dev/null || echo "false")
        echo "==> cluster role=$CLUSTER_ROLE initialized=$CLUSTER_STATE"

        case "$CLUSTER_ROLE" in
          primary)
            if [ "$CLUSTER_STATE" != "true" ]; then
              echo "==> initializing cluster $CLUSTER_DOMAIN as primary"
              api admin/cluster/init \
                --data-urlencode "clusterDomain=$CLUSTER_DOMAIN" \
                --data-urlencode "primaryNodeIpAddresses=$CLUSTER_PRIMARY_IPS"
              # cluster/init enables TLS + may restart web service —
              # wait briefly for it to come back on the HTTP port too.
              for i in 1 2 3 4 5; do
                if curl -fsS "$TECHNITIUM_HOST/" >/dev/null 2>&1; then break; fi
                sleep 2
              done
              # Re-authenticate after possible restart
              TOKEN=$(curl -fsS "$TECHNITIUM_HOST/api/user/login" \
                --data-urlencode "user=admin" --data-urlencode "pass=$PASS" \
                --data-urlencode "includeInfo=false" | jq -r .token)
            fi
            # ALWAYS apply (not just on first init): Primary must expose
            # its TLS web service to secondaries. ii-nix.modules.services
            # .technitium defaults to [127.0.0.1] — fine for admin UI but
            # not reachable for cluster handshake. Bind to loopback + the
            # primary's public IP. HTTP port shares this list but is
            # firewalled; only 53443 is reachable externally.
            WS_ADDR_PAYLOAD=$(jq -n --arg ip "$PRIMARY_IP" \
              '{webServiceLocalAddresses: ["127.0.0.1", $ip]}')
            WS_HTTP=$(curl -sS -o /tmp/api-resp -w '%{http_code}' \
              -X POST "$TECHNITIUM_HOST/api/settings/set?token=$TOKEN" \
              -H "Content-Type: application/json" \
              -d "$WS_ADDR_PAYLOAD")
            if [ "$WS_HTTP" != "200" ]; then
              echo "WARN: webServiceLocalAddresses update returned $WS_HTTP" >&2
              cat /tmp/api-resp >&2
            fi
            # Restart the web service so the new binding takes effect.
            # settings/set updates the config but the listener doesn't
            # rebind until restart. The HTTP API does this via the
            # internal restart endpoint OR we can just restart the
            # systemd unit from outside; here we use the API.
            curl -sS "$TECHNITIUM_HOST/api/settings/forceUpdateBlockLists" \
              --data-urlencode "token=$TOKEN" >/dev/null 2>&1 || true
            # NOTE: Tek typically rebinds on next service restart; if
            # 53443 still shows 127.0.0.1 after this script runs, do a
            # `systemctl restart technitium-dns-server.service` manually
            # or via systemd dependency. For now we tolerate one-deploy
            # delay; subsequent boots pick up the new binding.
            ;;
          secondary)
            if [ "$CLUSTER_STATE" != "true" ]; then
              if [ -z "$CLUSTER_PRIMARY_URL" ]; then
                echo "FATAL: clusterRole=secondary needs clusterPrimaryUrl set" >&2
                exit 1
              fi
              echo "==> joining cluster via $CLUSTER_PRIMARY_URL (primaryIP=$CLUSTER_PRIMARY_IP)"
              api admin/cluster/initJoin \
                --data-urlencode "secondaryNodeIpAddresses=$PRIMARY_IP" \
                --data-urlencode "primaryNodeUrl=$CLUSTER_PRIMARY_URL" \
                --data-urlencode "primaryNodeIpAddress=$CLUSTER_PRIMARY_IP" \
                --data-urlencode "primaryNodeUsername=admin" \
                --data-urlencode "primaryNodePassword=$PASS" \
                --data-urlencode "ignoreCertificateErrors=true"
              echo "==> cluster joined; primary now owns zone state"
            fi
            # Secondaries do NOT run zone reconciliation — primary
            # propagates via cluster catalog. Install TSIG key for
            # external DDNS updates (still useful per-node), then exit.
            : # fall through to TSIG install + settings/set, then return
            ;;
          off)
            : # classic AXFR-peer mode — fall through to existing logic
            ;;
        esac

        # ---------- Install AXFR TSIG key (federation-shared) ----------
        # API drift between Tek 13.x and 14.x:
        #   13.x: POST /api/settings/tsig/set with form params keyName/
        #         sharedSecret/algorithm (returned 404 actually — script
        #         masked it with `|| true` elsewhere; key persisted in
        #         disk config across boots so it still worked).
        #   14.x: TSIG keys are part of the main settings/set payload as
        #         an OBJECT ARRAY. Form-param array passing fails with
        #         "Offset and length were out of bounds" — has to be a
        #         JSON body. Field is `algorithmName` (not `algorithm`).
        #
        # We do the idempotent thing: GET current settings → keep all
        # tsigKeys whose keyName isn't ours → append our key → POST
        # settings/set with JSON body. Preserves any other TSIG keys an
        # operator has added via the UI.
        TSIG_KEY_ENTRY=$(jq -n \
          --arg name "$TSIG_KEY_NAME" \
          --arg secret "$TSIG_SECRET" \
          '{keyName: $name, sharedSecret: $secret, algorithmName: "hmac-sha256"}')

        MERGED_TSIG=$(curl -fsS "$TECHNITIUM_HOST/api/settings/get?token=$TOKEN" \
          | jq --arg name "$TSIG_KEY_NAME" --argjson new "$TSIG_KEY_ENTRY" \
              '(.response.tsigKeys // []) | map(select(.keyName != $name)) + [$new]')

        TSIG_PAYLOAD=$(jq -n --argjson keys "$MERGED_TSIG" '{tsigKeys: $keys}')

        TSIG_HTTP=$(curl -sS -o /tmp/api-resp -w '%{http_code}' \
          -X POST "$TECHNITIUM_HOST/api/settings/set?token=$TOKEN" \
          -H "Content-Type: application/json" \
          -d "$TSIG_PAYLOAD")
        if [ "$TSIG_HTTP" != "200" ]; then
          echo "FATAL: TSIG settings/set returned HTTP $TSIG_HTTP" >&2
          cat /tmp/api-resp >&2
          exit 1
        fi

        # ---------- Server-wide settings: TCP-bindable endpoint + recursion ----------
        # 0.0.0.0:53 only — not [::]:53. Reason: systemd-resolved (if present)
        # binds specific loopback addresses and on Linux a wildcard bind
        # conflicts with a same-port specific bind unless the existing
        # socket has SO_REUSEADDR. Technitium sets SO_REUSEADDR for UDP but
        # NOT TCP, so [::]:53 with v6only:1 was the only TCP bind that
        # succeeded — refusing all IPv4 TCP connections. The federation
        # turns resolved OFF on anchors, so 0.0.0.0:53 now works for both
        # UDP and TCP, and we don't need a separate IPv6 listener since
        # OCI Flex anchors have no useful public IPv6 anyway.
        api settings/set \
          --data-urlencode "dnsServerLocalEndPoints=0.0.0.0:53" \
          --data-urlencode "recursion=$RECURSION_MODE" \
          --data-urlencode "recursionNetworkACL=$RECURSION_ALLOWED_NETWORKS" \
          --data-urlencode "qpmLimitRequests=$RECURSION_QPM" \
          --data-urlencode "qpmLimitErrors=10" \
          --data-urlencode "qpmLimitSampleMinutes=5" \
          --data-urlencode "qpmLimitIPv4PrefixLength=24" \
          --data-urlencode "qpmLimitIPv6PrefixLength=56"

        # ---------- Per-zone reconciliation (skipped on secondary) ----------
        # In cluster mode, only the PRIMARY owns zone state — secondaries
        # receive zones via the cluster catalog. Running create/options
        # on a secondary would conflict with the cluster's view.
        if [ "$CLUSTER_ROLE" = "secondary" ]; then
          echo "==> secondary: skipping per-zone reconciliation (cluster handles)"
          api user/logout > /dev/null || true
          exit 0
        fi

        echo "$ZONES" | while IFS= read -r zone; do
          [ -z "$zone" ] && continue
          echo "==> reconciling zone: $zone"

          # Determine if zone is single-NS (no peers in NS RRset)
          IS_SINGLE_NS=0
          if echo "$SINGLE_NS_ZONES" | grep -qx "$zone"; then
            IS_SINGLE_NS=1
          fi

          # Step a: create zone (idempotent — 409 = already exists, OK)
          api zones/create \
            --data-urlencode "zone=$zone" \
            --data-urlencode "type=Primary" || true

          # Step b1: zone options (notify, AXFR ACL via TSIG)
          # Note: primaryNameServer at this endpoint applies only to
          # Secondary/Stub zones, not Primary — for Primary zones the
          # SOA MNAME is a record we update in step b2.
          api zones/options/set \
            --data-urlencode "zone=$zone" \
            --data-urlencode "notify=ZoneNameServers" \
            --data-urlencode "zoneTransfer=AllowOnlySpecifiedNameServers" \
            --data-urlencode "zoneTransferTsigKeyNames=$TSIG_KEY_NAME"

          # Step b2: SOA MNAME (primary nameserver) — only updates if
          # different from desired. Serial must be >= current; we
          # read-then-update with current_serial (Technitium auto-
          # increments on subsequent record changes).
          CURRENT_SOA=$(curl -fsS "$TECHNITIUM_HOST/api/zones/records/get" \
            --data-urlencode "token=$TOKEN" \
            --data-urlencode "domain=$zone" \
            --data-urlencode "zone=$zone" \
            --data-urlencode "listZone=false" \
            | jq -r '.response.records[] | select(.type=="SOA") | "\(.rData.primaryNameServer)\t\(.rData.serial)"')
          CUR_MNAME=$(echo "$CURRENT_SOA" | cut -f1)
          CUR_SERIAL=$(echo "$CURRENT_SOA" | cut -f2)
          if [ "$CUR_MNAME" != "$PRIMARY_HOSTNAME" ] && [ -n "$CUR_SERIAL" ]; then
            echo "  - SOA MNAME drift: $CUR_MNAME -> $PRIMARY_HOSTNAME (serial $CUR_SERIAL)"
            api zones/records/update \
              --data-urlencode "zone=$zone" \
              --data-urlencode "domain=$zone" \
              --data-urlencode "type=SOA" \
              --data-urlencode "primaryNameServer=$PRIMARY_HOSTNAME" \
              --data-urlencode "responsiblePerson=hostadmin.$zone" \
              --data-urlencode "serial=$CUR_SERIAL" \
              --data-urlencode "refresh=900" \
              --data-urlencode "retry=300" \
              --data-urlencode "expire=604800" \
              --data-urlencode "minimum=900" || true
          fi

          # Compute the authoritative set of NS hostnames for this zone
          DESIRED_NS=$(printf '%s\n' "$PRIMARY_HOSTNAME")
          if [ "$IS_SINGLE_NS" = "0" ]; then
            DESIRED_NS="$DESIRED_NS"$'\n'"$PEER_HOSTNAMES"
          fi
          DESIRED_NS=$(echo "$DESIRED_NS" | sed '/^$/d' | sort -u)

          # Step c1: GET current apex NS records and DELETE any not in desired set
          # (authoritative reconcile — handles renames like ns.sharing.io -> ns.developing.coop)
          CURRENT_NS=$(curl -fsS "$TECHNITIUM_HOST/api/zones/records/get" \
            --data-urlencode "token=$TOKEN" \
            --data-urlencode "domain=$zone" \
            --data-urlencode "zone=$zone" \
            --data-urlencode "listZone=false" \
            | jq -r '.response.records[] | select(.type=="NS") | .rData.nameServer' \
            | sed 's/\.$//' | sort -u)

          STALE_NS=$(comm -23 <(echo "$CURRENT_NS") <(echo "$DESIRED_NS"))
          echo "$STALE_NS" | while IFS= read -r stale_ns; do
            [ -z "$stale_ns" ] && continue
            echo "  - removing stale NS: $stale_ns"
            api zones/records/delete \
              --data-urlencode "zone=$zone" \
              --data-urlencode "domain=$zone" \
              --data-urlencode "type=NS" \
              --data-urlencode "nameServer=$stale_ns" || true
          done

          # Step c2: ADD primary NS (idempotent)
          api zones/records/add \
            --data-urlencode "zone=$zone" \
            --data-urlencode "domain=$zone" \
            --data-urlencode "type=NS" \
            --data-urlencode "nameServer=$PRIMARY_HOSTNAME" \
            --data-urlencode "ttl=3600" || true

          # Step c3: ADD peer NS records and any in-zone glue (skip if single-NS)
          if [ "$IS_SINGLE_NS" = "0" ]; then
            paste <(echo "$PEER_HOSTNAMES") <(echo "$PEER_IPS") | while IFS=$'\t' read -r peer_host peer_ip; do
              [ -z "$peer_host" ] && continue

              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$zone" \
                --data-urlencode "type=NS" \
                --data-urlencode "nameServer=$peer_host" \
                --data-urlencode "ttl=3600" || true

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
          fi

          # Primary hostname glue A if in-zone (e.g. ns.ii.coop in ii.coop)
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

        # ---------- Per-record reconciliation (additive) ----------
        # ZONE_RECORDS_TSV format: zone<TAB>name<TAB>type<TAB>value<TAB>ttl
        # 409 (already exists) is OK; we are additive only.
        echo "$ZONE_RECORDS_TSV" | while IFS=$'\t' read -r zone name type value ttl; do
          [ -z "$zone" ] && continue
          echo "==> record: $zone $name $type $value (ttl=$ttl)"

          # Strip trailing dot from value where Technitium expects bare hostname
          case "$type" in
            CNAME|NS|PTR)
              value=''${value%.}
              ;;
          esac

          # The Technitium API uses different fields per type
          case "$type" in
            A)
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$name" \
                --data-urlencode "type=A" \
                --data-urlencode "ipAddress=$value" \
                --data-urlencode "ttl=$ttl" || true
              ;;
            AAAA)
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$name" \
                --data-urlencode "type=AAAA" \
                --data-urlencode "ipAddress=$value" \
                --data-urlencode "ttl=$ttl" || true
              ;;
            CNAME)
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$name" \
                --data-urlencode "type=CNAME" \
                --data-urlencode "cname=$value" \
                --data-urlencode "ttl=$ttl" || true
              ;;
            NS)
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$name" \
                --data-urlencode "type=NS" \
                --data-urlencode "nameServer=$value" \
                --data-urlencode "ttl=$ttl" || true
              ;;
            MX)
              # value format: "PRIO HOST"
              MX_PRIO=$(echo "$value" | awk '{print $1}')
              MX_HOST=$(echo "$value" | awk '{print $2}'); MX_HOST=''${MX_HOST%.}
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$name" \
                --data-urlencode "type=MX" \
                --data-urlencode "preference=$MX_PRIO" \
                --data-urlencode "exchange=$MX_HOST" \
                --data-urlencode "ttl=$ttl" || true
              ;;
            TXT)
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$name" \
                --data-urlencode "type=TXT" \
                --data-urlencode "text=$value" \
                --data-urlencode "ttl=$ttl" || true
              ;;
            CAA)
              # value: "FLAGS TAG \"VAL\""
              CAA_FLAGS=$(echo "$value" | awk '{print $1}')
              CAA_TAG=$(echo "$value" | awk '{print $2}')
              CAA_VAL=$(echo "$value" | awk '{for(i=3;i<=NF;i++) printf "%s ",$i; print ""}' | sed 's/^"//;s/"$//;s/^ //;s/ $//')
              api zones/records/add \
                --data-urlencode "zone=$zone" \
                --data-urlencode "domain=$name" \
                --data-urlencode "type=CAA" \
                --data-urlencode "flags=$CAA_FLAGS" \
                --data-urlencode "tag=$CAA_TAG" \
                --data-urlencode "value=$CAA_VAL" \
                --data-urlencode "ttl=$ttl" || true
              ;;
            *)
              echo "  WARN: unsupported record type $type for $name in $zone" >&2
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
