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
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, disko }:
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
        # The keystone — generates users, groups, DNS, web, email, TLS
        # from a simple ii.domains + ii.users declaration
        domain-users = ./modules/domain-users.nix;

        # Service modules
        ghost = ./modules/services/ghost.nix;
        smtprelay = ./modules/services/smtprelay.nix;
        caddy-multi = ./modules/services/caddy-multi.nix;

        # Convenience: import everything
        default = { imports = [
          ./modules/domain-users.nix
          ./modules/services/ghost.nix
          ./modules/services/smtprelay.nix
          ./modules/services/caddy-multi.nix
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
