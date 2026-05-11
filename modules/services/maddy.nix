# ii/nix — Maddy MTA (thin federation wrapper over nixpkgs services.maddy)
#
# Maddy stays largely BARE here per architect: "nothing federation-specific to
# encode beyond expose-ports. Refactor when conventions emerge." This module
# is intentionally minimal — it just wires the hardening profile onto the
# upstream services.maddy systemd unit and provides federation-friendly
# defaults for the edge-anchored MX role.
#
# DECISIONS BAKED IN (need architect blessing):
#   - Use upstream services.maddy from nixpkgs as the implementation
#   - Apply managedRuntime hardening (Maddy is Go — could use staticBinary,
#     but managedRuntime is safer for any embedded Lua / future plugins)
#   - Ports: 25 (incoming SMTP), 587 (submission). 465 (SMTPS) optional.
#   - Hostname comes from networking.fqdn / config.networking.hostName
#
# OUT OF SCOPE (federation conventions to encode LATER):
#   - Domain → mailbox routing tables (per-tenant)
#   - DKIM key management (sops integration)
#   - Inbound spam/virus filtering policy
#   - Outbound relay configuration (Mailgun? upstream submission?)
#
# CONSUMER USAGE:
#   imports = [ ii-nix.nixosModules.maddy ];
#   services.maddy-federation = {
#     enable = true;
#     hostname = "mail.ii.coop";       # this MX server's identity
#     primaryDomain = "ii.coop";        # initial domain to accept
#     openFirewall = true;
#     enableSubmissions = false;        # 465 SMTPS (optional)
#   };
#
# Maddy's own configuration (services.maddy.config) is left to the consumer
# until conventions emerge — encoding policy here too early would lock in
# choices that the federation hasn't actually settled.
#
# ARCHITECT TODO: bless the minimal shape; confirm managedRuntime vs
# staticBinary; weigh in on whether to add per-domain configuration options
# now or wait for actual deployment to drive the conventions.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.maddy-federation;
  iiLib = (import ../../lib { inherit (pkgs) lib; });
in {
  options.services.maddy-federation = with lib; {
    enable = mkEnableOption "Maddy MTA with federation defaults";

    hostname = mkOption {
      type = types.str;
      example = "mail.ii.coop";
      description = "This server's announced SMTP hostname (EHLO/HELO).";
    };

    primaryDomain = mkOption {
      type = types.str;
      example = "ii.coop";
      description = ''
        Initial domain to accept mail for. Multi-domain support is left to
        consumer's services.maddy.config until federation conventions
        emerge.
      '';
    };

    enableSubmissions = mkOption {
      type = types.bool;
      default = false;
      description = "Enable port 465 (SMTPS) in addition to 587 (STARTTLS submission).";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Open TCP 25 (SMTP) + TCP 587 (submission) + optionally TCP 465
        (SMTPS) in the NixOS firewall.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Use upstream services.maddy; thin wrapper just sets hostname and
    # provides a starter config. Consumer overrides everything as needed.
    services.maddy = {
      enable = true;
      hostname = cfg.hostname;
      primaryDomain = cfg.primaryDomain;
      openFirewall = false;  # we manage firewall below
    };

    # Apply federation hardening profile to the upstream maddy unit
    systemd.services.maddy.serviceConfig = iiLib.hardening.managedRuntime // {
      # Maddy needs to bind ports 25, 465, 587 (all <1024)
      AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
      CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ 25 587 ] ++ lib.optional cfg.enableSubmissions 465;
    };
  };
}
