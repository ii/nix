# ii/nix — Technitium DNS server (bare service module)
#
# Wraps nixpkgs.technitium-dns-server 14.3.0 as a systemd-hardened service.
# Zone configuration is OUT OF SCOPE here — see modules/dns.nix for the
# federation wrapper that drives zones via the Technitium API.
#
# DECISIONS BAKED IN (need architect blessing):
#   - Native nixpkgs package, NOT a container
#   - Admin password from a file via DNS_SERVER_ADMIN_PASSWORD_FILE env var
#     (typically a sops-managed /run/secrets/ path)
#   - Admin UI (5380) bound to localhost only — NEVER firewalled. Reach via
#     SSH port-forward today; Authentik-in-front later via reverse proxy
#   - State directory: /var/lib/technitium (systemd StateDirectory=)
#   - Hardening profile: ii-nix.lib.hardening.managedRuntime
#     (.NET JIT requires MemoryDenyWriteExecute=false; this profile sets that
#     correctly while keeping every other isolation knob on)
#
# CONSUMER USAGE:
#   imports = [ ii-nix.nixosModules.technitium ];
#   services.technitium = {
#     enable = true;
#     adminPasswordFile = config.sops.secrets."technitium-admin-password".path;
#     dnsServerDomain = "ns.ii.coop";  # this server's announced hostname
#     openFirewall = true;             # opens 53/UDP+TCP at NixOS firewall
#   };
#
# ARCHITECT TODO: bless the option shape + hardening profile; confirm the
# native-not-container choice; confirm admin-UI-internal-only firewall policy.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.technitium;
  iiLib = (import ../../lib { inherit (pkgs) lib; });
in {
  options.services.technitium = with lib; {
    enable = mkEnableOption "Technitium authoritative DNS server";

    package = mkOption {
      type = types.package;
      default = pkgs.technitium-dns-server;
      defaultText = literalExpression "pkgs.technitium-dns-server";
      description = "Technitium package to use.";
    };

    adminPasswordFile = mkOption {
      type = types.path;
      description = ''
        Path to a file containing the Technitium admin password.
        Typically a sops-managed /run/secrets/ path. Required when first
        provisioning the server; subsequent restarts read from the
        embedded credential store.
      '';
    };

    dnsServerDomain = mkOption {
      type = types.str;
      default = "localhost";
      example = "ns.ii.coop";
      description = ''
        The DNS_SERVER_DOMAIN environment variable. Technitium uses this
        as the server's own hostname in SOA defaults and certain UI
        contexts. Set per-host to the public NS hostname this server
        anchors (e.g. ns.ii.coop on edge-iad, ns.developing.coop on
        edge-ord).
      '';
    };

    dataDir = mkOption {
      type = types.str;
      default = "/var/lib/technitium";
      description = "Persistent state directory (zones, config, logs).";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Open TCP+UDP 53 in the NixOS firewall. The Technitium admin UI
        (TCP 5380) is NEVER firewalled regardless of this setting; it
        binds to 127.0.0.1 only and is reached via SSH port-forward or
        a reverse-proxy fronted by SSO.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.technitium-dns-server = {
      description = "Technitium DNS Server (authoritative)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        DNS_SERVER_DOMAIN = cfg.dnsServerDomain;
        # DNS_SERVER_ADMIN_PASSWORD_FILE set in the ExecStart wrapper below —
        # it must point at $CREDENTIALS_DIRECTORY (a runtime-only systemd var
        # not expandable here) because DynamicUser=true cannot read the
        # /run/secrets/ path directly (sops files are root:root 0400).
        # Admin UI bound to loopback only — reachable via SSH port-forward
        DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES = "127.0.0.1";
      };

      serviceConfig = iiLib.hardening.managedRuntime // {
        ExecStart = pkgs.writeShellScript "technitium-start" ''
          export DNS_SERVER_ADMIN_PASSWORD_FILE="$CREDENTIALS_DIRECTORY/admin-password"
          exec ${cfg.package}/bin/technitium-dns-server ${cfg.dataDir}
        '';
        Restart = "always";
        RestartSec = "10s";

        # State directory — overrides DynamicUser's default location
        StateDirectory = "technitium";
        StateDirectoryMode = "0750";
        WorkingDirectory = cfg.dataDir;

        # Bind to privileged port 53 without running as root
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

        # Override managedRuntime's RestrictAddressFamilies — Technitium's
        # DhcpServer ctor runs unconditionally at startup (even when no
        # scopes are configured) and calls LinuxNetworkInterface
        # .GetLinuxNetworkInterfaces() which opens an AF_NETLINK socket
        # to enumerate interfaces. Without this, the service crashes
        # before ever loading config with "Address family not supported"
        # (errno 97), and on subsequent restarts hits a misleading
        # ArgumentNullException in CreateForwarderZoneToDisableDnssecForNTP
        # because the first crash leaves a partial empty auth.config.
        # AF_PACKET added defensively for raw-socket interface queries on
        # some kernels.
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" "AF_NETLINK" "AF_PACKET" ];

        # Admin password file readable by the dynamic user
        LoadCredential = [ "admin-password:${toString cfg.adminPasswordFile}" ];
      };
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ 53 ];
      allowedUDPPorts = [ 53 ];
    };
  };
}
