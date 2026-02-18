# ii/nix library functions
#
# Helper utilities for domain-user infrastructure.
# Imported as: ii-nix.lib

{ lib }:

{
  # Given a domain string like "ii.dev", return the short name "dev"
  # Given "abcs.news", return "abcs"
  domainShortName = domain:
    let parts = lib.splitString "." domain;
    in builtins.head parts;

  # Given a user and their domain list, generate all subdomains
  # userSubdomains "hh" ["dev" "nz"] { "dev" = "ii.dev"; "nz" = "ii.nz"; }
  # => ["hh.ii.dev" "hh.ii.nz"]
  userSubdomains = username: domainShortNames: domainMap:
    map (short: "${username}.${domainMap.${short}}") domainShortNames;

  # Generate a Caddy site block for a subdomain -> localhost:port
  caddySiteBlock = domain: port: ''
    ${domain} {
      reverse_proxy localhost:${toString port}
      header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        -Server
      }
    }
  '';
}
