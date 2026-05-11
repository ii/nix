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
# ARCHITECT TODO: bless this option shape; decide whether per-zone records
# (apex A, MX, etc.) belong here or in a separate ii-federation.dns.records
# submodule; confirm the API-call-via-ExecStartPost pattern vs zone file
# generation; review the TSIG ACL approach.

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
    # SKETCH — actual implementation depends on architect's blessing of
    # the API-call vs zone-file approach.
    systemd.services.technitium-federation-reconcile = {
      description = "Reconcile Technitium zones against federation config";
      after = [ "technitium-dns-server.service" ];
      bindsTo = [ "technitium-dns-server.service" ];
      wantedBy = [ "multi-user.target" ];

      script = ''
        # TODO ARCHITECT-BLESS: zone-reconciliation mechanism
        # - Authenticate to http://127.0.0.1:5380/api/user/login with admin password
        # - For each zone in cfg.zones:
        #   - Create if missing (idempotent: 409 means exists, ignore)
        #   - Set SOA with primaryHostname + responsiblePerson
        #   - Add NS records for primaryHostname + all peer hostnames
        #   - Install TSIG key (read tsigKeyFile)
        #   - Apply AXFR ACL: only peer IPs
        echo "stub — implementation pending architect blessing of mechanism"
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
