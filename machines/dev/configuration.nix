# dev — BM.DenseIO.E5.128 base OS (ii.dev)
#
# Minimal NixOS to get the box running.
# Services (Ghost, Caddy, etc.) come later via ii.services.

{ config, lib, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
    ./disko.nix
  ];

  networking.hostName = "dev";
  time.timeZone = "UTC";
  system.stateVersion = "24.11";

  # Boot
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # Serial console for OCI console connection
  boot.kernelParams = [
    "console=tty0"
    "console=ttyS0,115200"
  ];

  # OCI bare metal networking
  networking.firewall.checkReversePath = "loose";
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 25 80 443 587 ];
    allowedUDPPorts = [ 53 41641 ]; # DNS + Tailscale
  };

  # Main user — ii@dev, email ii@ii.dev
  users.users.ii = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    shell = pkgs.zsh;
    description = "ii.dev";
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICwsHmQtv++obVtbu8Nc9COPOLEG5N12jYk75dTCaRsT hh@nextral.sharing.io"
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIItrB/8JpOZIyhp00TSKPxLOs3ZsqGBciIkCJi+SyjzJ hh@m1.medusa.local"
    ];
  };

  # Root key for nixos-anywhere
  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICwsHmQtv++obVtbu8Nc9COPOLEG5N12jYk75dTCaRsT hh@nextral.sharing.io"
  ];

  # SSH
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
    };
  };

  # Tailscale
  services.tailscale.enable = true;

  # Basics
  programs.zsh.enable = true;
  environment.systemPackages = with pkgs; [
    vim git htop tmux curl jq
    nvme-cli smartmontools
  ];

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    trusted-users = [ "root" "ii" ];
  };
}
