# disko.nix — Disk layout for BM.DenseIO.E5.128
#
# 12× Intel SSDPF2KX076T1S (6.80 TB each)
#
# Layout:
#   nvme0n1, nvme1n1: Boot mirror (ESP + root ZFS mirror)
#     - 1G ESP partition (FAT32, mirrored via systemd-boot)
#     - 80G root partition (ZFS mirror for OS)
#     - Rest: ZFS data pool
#   nvme2n1 .. nvme11n1: ZFS data pool (remaining 10 drives)
#
# Total: ~80G mirrored root, ~81TB data pool

{ ... }:

{
  disko.devices = {
    disk = {
      # Boot drive 1
      nvme0 = {
        type = "disk";
        device = "/dev/nvme0n1";
        content = {
          type = "gpt";
          partitions = {
            ESP = {
              size = "1G";
              type = "EF00";
              content = {
                type = "filesystem";
                format = "vfat";
                mountpoint = "/boot";
                mountOptions = [ "umask=0077" ];
              };
            };
            root = {
              size = "80G";
              content = {
                type = "zfs";
                pool = "rpool";
              };
            };
            data = {
              size = "100%";
              content = {
                type = "zfs";
                pool = "dpool";
              };
            };
          };
        };
      };

      # Boot drive 2 (mirror partner)
      nvme1 = {
        type = "disk";
        device = "/dev/nvme1n1";
        content = {
          type = "gpt";
          partitions = {
            ESP = {
              size = "1G";
              type = "EF00";
              content = {
                type = "filesystem";
                format = "vfat";
                mountpoint = "/boot-fallback";
                mountOptions = [ "umask=0077" ];
              };
            };
            root = {
              size = "80G";
              content = {
                type = "zfs";
                pool = "rpool";
              };
            };
            data = {
              size = "100%";
              content = {
                type = "zfs";
                pool = "dpool";
              };
            };
          };
        };
      };

      # Data drives 3-12
      nvme2  = { type = "disk"; device = "/dev/nvme2n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme3  = { type = "disk"; device = "/dev/nvme3n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme4  = { type = "disk"; device = "/dev/nvme4n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme5  = { type = "disk"; device = "/dev/nvme5n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme6  = { type = "disk"; device = "/dev/nvme6n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme7  = { type = "disk"; device = "/dev/nvme7n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme8  = { type = "disk"; device = "/dev/nvme8n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme9  = { type = "disk"; device = "/dev/nvme9n1";  content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme10 = { type = "disk"; device = "/dev/nvme10n1"; content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
      nvme11 = { type = "disk"; device = "/dev/nvme11n1"; content = { type = "gpt"; partitions.data = { size = "100%"; content = { type = "zfs"; pool = "dpool"; }; }; }; };
    };

    # Root pool — mirror across nvme0 + nvme1 (80G each)
    zpool = {
      rpool = {
        type = "zpool";
        mode = "mirror";
        rootFsOptions = {
          compression = "zstd";
          "com.sun:auto-snapshot" = "false";
          mountpoint = "none";
        };
        datasets = {
          "root" = {
            type = "zfs_fs";
            mountpoint = "/";
            options.mountpoint = "legacy";
          };
          "nix" = {
            type = "zfs_fs";
            mountpoint = "/nix";
            options.mountpoint = "legacy";
          };
          "home" = {
            type = "zfs_fs";
            mountpoint = "/home";
            options.mountpoint = "legacy";
          };
          "var" = {
            type = "zfs_fs";
            mountpoint = "/var";
            options.mountpoint = "legacy";
          };
        };
      };

      # Data pool — RAIDZ2 across 12 partitions (10 data + 2 from boot drives)
      # ~81TB raw, ~54TB usable with RAIDZ2 (2 drive parity)
      dpool = {
        type = "zpool";
        mode = "raidz2";
        rootFsOptions = {
          compression = "zstd";
          mountpoint = "none";
        };
        datasets = {
          "data" = {
            type = "zfs_fs";
            mountpoint = "/data";
            options.mountpoint = "legacy";
          };
          "ghost" = {
            type = "zfs_fs";
            mountpoint = "/var/lib/ghost";
            options.mountpoint = "legacy";
          };
        };
      };
    };
  };
}
