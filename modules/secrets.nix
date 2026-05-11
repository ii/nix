# ii/nix — secrets module (federation-canonical sops-nix configuration)
#
# Federation interface for encrypted secrets. Current implementation: sops-nix.
# The abstraction layer ("secrets.nix") is what consumers depend on; swapping
# to age-direct / vault-nix / agenix later only swaps the impl, not consumers.
#
# DECRYPTION MODEL
#   Each machine uses its own SSH host key (derived to age via ssh-to-age) as
#   its decryption identity. No separate age key files to manage. The SSH host
#   key already lives on the box from initial provisioning and is covered by
#   whatever host-key backup the machine has.
#
# RECIPIENT POLICY (enforced in each repo's .sops.yaml, not here)
#   - the machine's own SSH-host-key-derived age pubkey
#   - the director's age pubkey
# Cross-machine secrets enumerate additional recipients per-secret —
# minimum-privilege, no auto-fanout to all federation machines.
#
# CONSUMER USAGE — ONE-IMPORT STORY (architect-blessed transitive):
#
#     imports = [ ii-nix.nixosModules.secrets ];
#
# nixosModules.secrets bundles sops-nix.nixosModules.sops transitively
# via flake.nix, so consumers don't have to remember to add sops-nix.
# ii/nix's flake.nix pins the tested-against sops-nix version.
#
# PROVENANCE
#   Copied verbatim from iinix nixos/modules/ii-federation/secrets.nix
#   (commit 174736a, 2026-05-11). iinix retains its local copy through the
#   transition; mass-move happens after architect blesses this home.

{ ... }:

{
  sops = {
    defaultSopsFormat = "yaml";
    age.sshKeyPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];
  };
}
