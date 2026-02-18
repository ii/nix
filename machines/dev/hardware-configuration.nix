# hardware-configuration.nix — BM.DenseIO.E5.128
# Generated from capture data 2026-02-18
#
# CPU: 2× AMD EPYC 9J14 (Genoa), 128 cores / 256 threads
# RAM: 1.5 TiB
# NVMe: 12× Intel SSDPF2KX076T1S (6.80 TB each)
# NIC: 2× Mellanox ConnectX (mlx5_core), 100 Gbps
# Boot: NVMe (systemd-boot)

{ config, lib, pkgs, modulesPath, ... }:

{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
  ];

  # Kernel — 6.12 for ZFS compatibility + Genoa support
  # linuxPackages_latest (6.15+) breaks ZFS (zfs-kernel marked broken)
  boot.kernelPackages = pkgs.linuxPackages_6_12;

  # Kernel modules needed at boot (from capture lsmod)
  boot.initrd.availableKernelModules = [
    "nvme"          # NVMe storage
    "ahci"          # SATA (if any)
    "xhci_pci"      # USB
    "mlx5_core"     # Mellanox ConnectX NICs
  ];

  boot.initrd.kernelModules = [ ];

  boot.kernelModules = [
    "kvm-amd"       # KVM virtualization (AMD-V)
  ];

  boot.extraModulePackages = [ ];

  # ZFS support
  boot.supportedFilesystems = [ "zfs" ];
  boot.zfs.forceImportRoot = false;
  networking.hostId = "e5128001"; # Required for ZFS, 8 hex chars

  # Network — Mellanox ConnectX dual-port
  # ens300np0: primary (MTU 9000, 100Gbps)
  # ens340np0: secondary (MTU 1500)
  networking.useDHCP = true;

  # NUMA-aware — 2 sockets, 2 NUMA nodes
  # Node 0: CPUs 0-63, 128-191
  # Node 1: CPUs 64-127, 192-255
  hardware.cpu.amd.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;

  # NVMe — 12 drives, all Intel P5800X class
  # /dev/nvme0n1 through /dev/nvme11n1
  # Each 6.80 TB, 512B sectors

  # Firmware
  hardware.enableRedistributableFirmware = true;
}
