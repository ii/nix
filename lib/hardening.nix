# ii/nix — systemd hardening profiles
#
# Federation-canonical baseline for service hardening. Two profiles:
#
#   - managedRuntime: for JIT/managed-runtime services (.NET, JVM, Erlang).
#     MemoryDenyWriteExecute=false because the runtime needs writable
#     executable pages for JIT code. All other isolation knobs ON.
#
#   - staticBinary: for native compiled services (Go, Rust, C).
#     MemoryDenyWriteExecute=true (no JIT means W^X is safe).
#     LockPersonality=true.
#
# Applied via:
#   serviceConfig = ii-nix.lib.hardening.managedRuntime;
# Or:
#   serviceConfig = ii-nix.lib.hardening.managedRuntime // {
#     # service-specific overrides:
#     StateDirectory = "myservice";
#     AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
#   };
#
# ARCHITECT TODO: bless or refine this dictionary as the federation canonical
# hardening baseline; docs/architect/federation-hardening-baseline.md captures
# rationale when written.

{ lib }:

let
  managedRuntime = {
    DynamicUser = true;

    # JIT-friendly: W^X NOT enforced (runtime needs writable exec pages)
    MemoryDenyWriteExecute = false;

    # Privilege & capability bounding (services that need port <1024 add
    # CAP_NET_BIND_SERVICE to AmbientCapabilities + CapabilityBoundingSet)
    CapabilityBoundingSet = [ ];
    AmbientCapabilities = [ ];
    NoNewPrivileges = true;

    # Filesystem
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";

    # Kernel / cgroup / clock isolation
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;

    # Privilege & namespace restrictions
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    RestrictNamespaces = true;
    RemoveIPC = true;
    RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];

    # Syscalls
    SystemCallArchitectures = "native";
    SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
  };

  staticBinary = managedRuntime // {
    MemoryDenyWriteExecute = true;
    LockPersonality = true;
  };
in
{
  hardening = {
    inherit managedRuntime staticBinary;
  };
}
