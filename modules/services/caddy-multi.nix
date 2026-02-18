# caddy-multi.nix — Multi-domain Caddy reverse proxy
#
# Reads from config.ii.generated to auto-generate virtual hosts
# for all registered domains and user subdomains.
#
# For each domain user's Ghost instance, creates:
#   - HTTPS site with reverse proxy to Ghost port
#   - www → apex redirect
#   - Security headers
#   - Static asset caching
#
# ACME is handled by Caddy automatically (HTTP-01 or DNS-01).
# When Technitium is the authoritative nameserver and Caddy uses
# its API for DNS-01, certs are instant (no propagation delay).
#
# Usage:
#   ii.services.caddy = {
#     enable = true;
#     adminEmail = "hh@ii.coop";
#     sites = {
#       "abcs.news" = { upstream = "localhost:2368"; };
#       "hh.ii.dev" = { upstream = "localhost:3000"; };
#     };
#   };

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.ii.services.caddy;
in
{
  options.ii.services.caddy = {
    enable = mkEnableOption "Multi-domain Caddy reverse proxy";

    adminEmail = mkOption {
      type = types.str;
      default = "hh@ii.coop";
      description = "Email for ACME certificate registration";
    };

    sites = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          upstream = mkOption {
            type = types.str;
            description = "Upstream address (e.g. localhost:2368)";
          };

          extraConfig = mkOption {
            type = types.lines;
            default = "";
            description = "Extra Caddyfile directives for this site";
          };

          enableWwwRedirect = mkOption {
            type = types.bool;
            default = true;
            description = "Redirect www.domain to domain";
          };
        };
      });
      default = {};
      description = "Site definitions, keyed by domain name";
    };

    globalConfig = mkOption {
      type = types.lines;
      default = "";
      description = "Extra global Caddyfile options";
    };
  };

  config = mkIf cfg.enable {
    services.caddy = {
      enable = true;
      email = cfg.adminEmail;
      globalConfig = cfg.globalConfig;

      # Generate a virtualHost for each site
      virtualHosts = let
        # Primary sites
        primaryHosts = mapAttrs (domain: siteCfg: {
          extraConfig = ''
            reverse_proxy ${siteCfg.upstream}

            header {
              X-Content-Type-Options "nosniff"
              X-Frame-Options "SAMEORIGIN"
              Referrer-Policy "strict-origin-when-cross-origin"
              Strict-Transport-Security "max-age=31536000; includeSubDomains"
              -Server
            }

            @static path *.css *.js *.png *.jpg *.jpeg *.gif *.svg *.woff *.woff2
            header @static Cache-Control "public, max-age=604800"

            ${siteCfg.extraConfig}
          '';
        }) cfg.sites;

        # www redirects
        wwwRedirects = mapAttrs' (domain: siteCfg:
          nameValuePair "www.${domain}" {
            extraConfig = ''
              redir https://${domain}{uri} permanent
            '';
          }
        ) (filterAttrs (_: siteCfg: siteCfg.enableWwwRedirect) cfg.sites);

      in primaryHosts // wwwRedirects;
    };

    # Caddy needs to bind to privileged ports
    systemd.services.caddy.serviceConfig = {
      AmbientCapabilities = "CAP_NET_BIND_SERVICE";
      CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
    };
  };
}
