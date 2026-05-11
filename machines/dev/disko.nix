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
#
# Storage architecture: /srv is the data root (FHS compliant)
#   /srv/tenants/{name}/ — per-tenant datasets (domain = user = portable bundle)
#   Migration: zfs send -R dpool/srv/tenants/{name} captures everything
#   See: /var/srv/recall/agent-sync/storage-architecture.md

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
    # Lean: only boot-critical OS state. No user data, no tenant data.
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
          "var" = {
            type = "zfs_fs";
            mountpoint = "/var";
            options.mountpoint = "legacy";
          };
          # NOTE: /home moved to dpool — rpool is for OS only
        };
      };

      # Data pool — RAIDZ2 across 12 partitions (10 data + 2 from boot drives)
      # ~81TB raw, ~60TB usable with RAIDZ2 (2 drive parity)
      #
      # Architecture:
      #   /home/{user}           — human users (interactive, per-user datasets)
      #   /srv/tenants/{name}/   — domain tenants (portable service bundles)
      #   /srv/shared/           — platform services (dns, depot, bao)
      #
      # Naming: shortnames (abcs, dev) map to FQDNs via ii.domains NixOS option.
      #   abcs → abcs.news, dev → ii.dev. Single source of truth in NixOS config.
      #
      # Migration: zfs send -R dpool/srv/tenants/{name}@snap → full tenant transfer
      dpool = {
        type = "zpool";
        mode = "raidz2";
        rootFsOptions = {
          compression = "zstd";
          atime = "off";
          xattr = "sa";
          dnodesize = "auto";
          mountpoint = "none";
        };
        datasets = {

          # ══════════════════════════════════════════════════════════
          # SAFETY: 3T reservation — ZFS degrades badly above 95% full.
          # Destroy this dataset to free emergency space for cleanup.
          # ══════════════════════════════════════════════════════════
          "reserved" = {
            type = "zfs_fs";
            options = {
              mountpoint = "none";
              canmount = "off";
              reservation = "3T";
            };
          };

          # ══════════════════════════════════════════════════════════
          # /home — human user homes (moved from rpool for capacity)
          # Per-user child datasets for quotas + independent snapshots
          # ══════════════════════════════════════════════════════════
          "home" = {
            type = "zfs_fs";
            mountpoint = "/home";
            options.mountpoint = "legacy";
          };
          "home/hh" = {
            type = "zfs_fs";
            mountpoint = "/home/hh";
            options = {
              mountpoint = "legacy";
              refquota = "500G"; # wheel user, director
            };
          };
          "home/ash" = {
            type = "zfs_fs";
            mountpoint = "/home/ash";
            options = {
              mountpoint = "legacy";
              refquota = "200G";
            };
          };
          "home/ben" = {
            type = "zfs_fs";
            mountpoint = "/home/ben";
            options = {
              mountpoint = "legacy";
              refquota = "200G";
            };
          };
          "home/shalom" = {
            type = "zfs_fs";
            mountpoint = "/home/shalom";
            options = {
              mountpoint = "legacy";
              refquota = "200G";
            };
          };

          # ══════════════════════════════════════════════════════════
          # /srv — FHS service data root
          # ══════════════════════════════════════════════════════════
          "srv" = {
            type = "zfs_fs";
            mountpoint = "/srv";
            options.mountpoint = "legacy";
          };

          # ── Tenants (organizational parent, not mounted) ────────
          "srv/tenants" = {
            type = "zfs_fs";
            options = {
              mountpoint = "none";
              canmount = "off";
            };
          };

          # ── abcs.news tenant (shortname: abcs, uid: 2001) ──────
          # Service account home = /srv/tenants/abcs
          "srv/tenants/abcs" = {
            type = "zfs_fs";
            mountpoint = "/srv/tenants/abcs";
            options = {
              mountpoint = "legacy";
              quota = "1T";       # director decision: 1T per tenant initially
            };
          };
          "srv/tenants/abcs/ghost" = {
            type = "zfs_fs";
            mountpoint = "/srv/tenants/abcs/ghost";
            options = {
              mountpoint = "legacy";
              recordsize = "64K"; # SQLite DB + content blobs
            };
          };
          "srv/tenants/abcs/mail" = {
            type = "zfs_fs";
            mountpoint = "/srv/tenants/abcs/mail";
            options.mountpoint = "legacy";
          };

          # ── ii.dev tenant (shortname: dev, uid: 2000) ──────────
          # Service account home = /srv/tenants/dev
          "srv/tenants/dev" = {
            type = "zfs_fs";
            mountpoint = "/srv/tenants/dev";
            options = {
              mountpoint = "legacy";
              quota = "1T";       # director decision: 1T per tenant initially
            };
          };
          "srv/tenants/dev/web" = {
            type = "zfs_fs";
            mountpoint = "/srv/tenants/dev/web";
            options.mountpoint = "legacy";
          };
          "srv/tenants/dev/mail" = {
            type = "zfs_fs";
            mountpoint = "/srv/tenants/dev/mail";
            options.mountpoint = "legacy";
          };

          # ══════════════════════════════════════════════════════════
          # /srv/shared — platform services (not per-tenant)
          # ══════════════════════════════════════════════════════════
          "srv/shared" = {
            type = "zfs_fs";
            mountpoint = "/srv/shared";
            options.mountpoint = "legacy";
          };
          "srv/shared/dns" = {
            type = "zfs_fs";
            mountpoint = "/srv/shared/dns";
            options = {
              mountpoint = "legacy";
              recordsize = "16K"; # Technitium SQLite database
              refquota = "10G";
            };
          };
          "srv/shared/depot" = {
            type = "zfs_fs";
            mountpoint = "/srv/shared/depot";
            options = {
              mountpoint = "legacy";
              refquota = "50G";
            };
          };
          "srv/shared/bao" = {
            type = "zfs_fs";
            mountpoint = "/srv/shared/bao";
            options = {
              mountpoint = "legacy";
              refquota = "10G";
            };
          };
          "srv/shared/caddy" = {
            type = "zfs_fs";
            mountpoint = "/srv/shared/caddy";
            options = {
              mountpoint = "legacy";
              refquota = "5G";    # ACME certs + config
            };
          };

          # ── Backup receive target ───────────────────────────────
          "srv/backup" = {
            type = "zfs_fs";
            mountpoint = "/srv/backup";
            options.mountpoint = "legacy";
          };

          # ── Container storage (Podman/OCI images) ───────────────
          "containers" = {
            type = "zfs_fs";
            mountpoint = "/var/lib/containers";
            options = {
              mountpoint = "legacy";
              refquota = "200G";
            };
          };
        };
      };
    };
  };
}
