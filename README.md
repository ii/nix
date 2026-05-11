# ii/nix — shared NixOS modules for the ii federation

Federation-canonical NixOS modules consumed by federation machines
(bare metal hosts, edge VMs, future cluster nodes). Two layers:

- **Federation interface modules** (`modules/*.nix`) — the abstraction
  layer. Encode federation conventions (zone lists, recipient policies,
  hardening profiles). Stable API; impl can change.
- **Bare service modules** (`modules/services/*.nix`) — concrete
  service definitions. Apply federation hardening helpers from
  `lib/hardening.nix`; expose service-specific options.

## What's here

### Federation interface modules

| Module                  | Purpose                                                  |
|-------------------------|----------------------------------------------------------|
| `modules/domain-users.nix` | Keystone — generates users, groups, DNS, web, email, TLS from `ii.domains` + `ii.users` declaration |
| `modules/secrets.nix`   | sops-nix-backed encrypted secrets (SSH-host-key-as-age-key pattern) |
| `modules/dns.nix`       | Federation authoritative DNS (zone list, TSIG, AXFR ACLs) over Technitium |
| `modules/certs.nix`     | Federation wildcard TLS via ACME DNS-01; auto-resolves from `dns.nix` |

### Bare service modules

| Module                             | Service                              |
|------------------------------------|--------------------------------------|
| `modules/services/ghost.nix`       | Ghost CMS (per-tenant blog/site)     |
| `modules/services/smtprelay.nix`   | Outbound SMTP relay (Mailgun, etc.)  |
| `modules/services/caddy-multi.nix` | Multi-site Caddy reverse proxy       |
| `modules/services/technitium.nix`  | Technitium DNS (authoritative)       |
| `modules/services/maddy.nix`       | Maddy MTA (inbound + submission)     |
| `modules/services/acme-dns01.nix`  | Lego-based ACME DNS-01 client        |

### Library helpers

`lib/hardening.nix` exports `hardening.managedRuntime` and
`hardening.staticBinary` — systemd hardening profiles that get
applied via `serviceConfig = ii-nix.lib.hardening.managedRuntime;`.

`lib/default.nix` exports domain/user helper functions
(`domainShortName`, `userSubdomains`, `caddySiteBlock`).

## Usage

```nix
# In a machine depot's flake.nix:
inputs.ii-nix.url = "github:ii/nix";

# In the machine config:
{
  imports = [
    ii-nix.nixosModules.secrets    # sops-nix configured per federation
    ii-nix.nixosModules.dns         # authoritative DNS
    ii-nix.nixosModules.certs       # wildcard TLS
  ];

  ii-federation.dns = {
    enable = true;
    primaryHostname = "ns.ii.coop";
    primaryIP = "129.158.209.28";
    zones = [ "ii.coop" "ii.dev" "developing.coop" ];
    tsigKeyFile = config.sops.secrets."dns-axfr-tsig".path;
    adminPasswordFile = config.sops.secrets."technitium-admin-password".path;
  };

  ii-federation.certs = {
    enable = true;
    email = "hostmaster@ii.coop";
    # domains defaults to wildcards + apex over each declared zone
  };
}
```

For the federation edge bundle (DNS + MX + ACME), use the convenience
import:

```nix
imports = [ ii-nix.nixosModules.edge ];
```

## Historical note on naming

The original Gen 1 three-tier plan reserved `ii/nix` for upstreamable
stdlib helpers (`mkSystem`, `mkHome`, `treefmt`) and proposed
`ii/federation` as a separate home for federation-opinionated modules.

Reality diverged: `ii/nix` was populated with federation modules from
the start (Feb 18 initial commit shipped `domain-users.nix`,
`ghost.nix`, `smtprelay.nix`, `caddy-multi.nix`). The "stdlib-only
reservation" was an abstract intention that the implementation
outgrew before the second commit.

Decision recorded 2026-05-11: `ii/nix` IS the federation modules
home. The stdlib-reservation framing is historical, not aspirational.
Any future upstreamable stdlib (if it emerges as a real need) gets
its own repo at that time.

## References

This is the **NixOS modules half** of the federation DNS+infra pattern.
The complementary **Terraform half** lives at:

- `/var/srv/infra/terraform/dns-federation/` (GitLab) — terraform
  modules for Cloudflare zone management (`cf-domain`) and registrar
  NS delegation (`ns-domain`)

Two-way cross-reference: that README's §References points back here.

## Related federation runbooks

- `/var/srv/recall/agent-state/ii-mgr.org` §Federation Architecture —
  the per-zone-migration state machine and CF-isolation runbook
- `/var/srv/recall/agent-state/ii-ii-oci.org` — the BM5 box owner's
  state file (consumer of these modules)
- `/var/srv/recall/agent-state/ii-coops-mgr.org` — `developing.coop`
  federation-domain owner

## Architect review

The 2026-05-11 federation-edge-boxes work added `secrets.nix`,
`dns.nix`, `certs.nix`, `lib/hardening.nix`, `technitium.nix`,
`maddy.nix`, `acme-dns01.nix` as **sketches pending architect-mgr
review**. Each module's header comment notes what specifically needs
architect blessing. Once blessed, the sketch promotes to a federation
primitive citable by other federation work.
