# ii/nix — Shared NixOS module library for ii infrastructure
#
# Layer 1 of the three-tier composition:
#   Layer 1: ii/nix     — shared modules (this repo)
#   Layer 2: ii/dev     — machine depot (who's on this box)
#   Layer 3: hh/hh      — per-user depot (how I want my env)
#
# Usage in a machine depot's flake.nix:
#   inputs.ii-nix.url = "github:ii/nix";
#   modules = [ ii-nix.nixosModules.default ];
#
# Then declare:
#   ii.domains = { "ii.dev" = { gid = 3000; }; };
#   ii.users = { hh = { uid = 1000; domains = ["dev"]; isAdmin = true; }; };
{
  description = "ii shared NixOS modules — domain=user infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    # Newer pin used ONLY to pull technitium-dns-server 14.3.0 (with
    # cluster + cluster-catalog support, which doesn't exist in
    # nixos-24.11's 13.0.2 build). Anchor systems still build against
    # nixos-24.11 for everything else; the overlay below substitutes
    # just the technitium-dns-server package out of unstable.
    # Why a separate pin: 14.3.0 needs .NET 9; 24.11 packages 13.0.2
    # against .NET 8 with a regenerated nuget-deps.json. Pulling the
    # whole derivation (including the nuget-deps + libmsquic 9.x +
    # .NET 9 runtime closure) from a tree that has them is much
    # easier than back-porting.
    #
    # nixpkgs-unstable (NOT master) so cache.nixos.org has all the
    # closure built — master HEAD often isn't fully cached yet.
    nixpkgs-master.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # sops-nix is transitively bundled by nixosModules.secrets so consumers
    # get the federation-canonical secrets layer in a single import. Pin
    # tested-against version here; consumers don't have to remember.
    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixpkgs-master, disko, sops-nix }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      # ============================================================
      # Machine configurations (nixos-anywhere targets)
      # ============================================================

      nixosConfigurations.dev = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          disko.nixosModules.disko
          self.nixosModules.default
          ./machines/dev/configuration.nix
        ];
      };

      # ============================================================
      # NixOS Modules (the main export)
      # ============================================================

      nixosModules = {
        # ===== Federation interface modules (the abstraction layer) =====
        # The keystone — generates users, groups, DNS, web, email, TLS
        # from a simple ii.domains + ii.users declaration
        domain-users = ./modules/domain-users.nix;

        # sops-nix-backed encrypted secrets convention (federation primitive).
        # Bundles sops-nix transitively — a single import wires both.
        secrets = {
          imports = [
            sops-nix.nixosModules.sops
            ./modules/secrets.nix
          ];
        };

        # Federation DNS — wraps services.technitium with zone lists,
        # TSIG-from-secrets, ACLs. Consumers import this for the
        # ii-federation.dns.* options.
        dns = ./modules/dns.nix;

        # Federation wildcard TLS — wraps services.acme-dns01 with
        # auto-resolved DNS-01 target + shared TSIG key from dns.nix.
        certs = ./modules/certs.nix;

        # ===== Bare service modules (concrete implementations) =====
        ghost = ./modules/services/ghost.nix;
        smtprelay = ./modules/services/smtprelay.nix;
        caddy-multi = ./modules/services/caddy-multi.nix;
        technitium = ./modules/services/technitium.nix;
        maddy = ./modules/services/maddy.nix;
        acme-dns01 = ./modules/services/acme-dns01.nix;

        # Overlay: replace nixos-24.11's technitium-dns-server (13.0.2,
        # no clustering) with nixpkgs-master's (14.3.0, has clustering).
        # Pulled in by the anchor bundle below; consumers that don't
        # need clustering can skip it and keep 13.0.2.
        technitium-14 = { ... }: {
          nixpkgs.overlays = [
            (final: prev: {
              technitium-dns-server =
                nixpkgs-master.legacyPackages.${prev.system}.technitium-dns-server;
            })
          ];
        };

        # Convenience: import everything legacy + federation
        default = { imports = [
          ./modules/domain-users.nix
          ./modules/services/ghost.nix
          ./modules/services/smtprelay.nix
          ./modules/services/caddy-multi.nix
        ]; };

        # Convenience: federation anchor bundle (DNS + MX + ACME).
        # 'Anchor' replaces the original 'edge' framing: these boxes ARE the
        # federation's authoritative outermost point (a stable bind target +
        # identity anchor), not proxies between internal/external. Naming
        # decision per architect 2026-05-11.
        anchor = { imports = [
          ./modules/secrets.nix
          ./modules/dns.nix
          ./modules/certs.nix
          ./modules/services/technitium.nix
          ./modules/services/maddy.nix
          ./modules/services/acme-dns01.nix
          # Pull technitium-dns-server 14.3.0 from nixpkgs-master via
          # overlay. 14.x is the first version with cluster + cluster
          # catalog (required for the federation sync model in
          # dns.nix); nixos-24.11's 13.0.2 doesn't have either.
          self.nixosModules.technitium-14
        ]; };
      };

      # ============================================================
      # Library functions
      # ============================================================

      lib = import ./lib { inherit (nixpkgs) lib; };

      # ============================================================
      # Dev shell for working on these modules
      # ============================================================

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [ nil nixpkgs-fmt ];
          };
        }
      );
    };
}
