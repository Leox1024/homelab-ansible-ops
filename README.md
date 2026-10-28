# homelab automation — Semaphore + Ansible

Ansible playbooks to maintain the VMs, LXCs and services of a small homelab.
They are written to be run from [Semaphore UI](https://github.com/semaphoreui/semaphore),
but work just as well with plain `ansible-playbook`.

## Layout

```
playbooks/
├── checkmk/     Checkmk local checks (files/ holds the check scripts)
├── docker/      Docker hosts maintenance
├── linux/       generic Debian/Ubuntu tasks (logs, SSH, cleanup, health check)
├── network/     firewall and switch configuration backups
├── nextcloud/   Nextcloud maintenance and its TLS certificate
├── proxmox/     Proxmox VE nodes and VM provisioning
└── tang/        Tang servers for the automatic unlock of encrypted VMs
extras/
└── grafana-dashboards/   dashboard exports, not used by Ansible
```

| Playbook | What it does |
|---|---|
| `checkmk/deploy-local-check.yml` | deploys the `900_security_watch` Checkmk local check |
| `docker/prune.yml` | prunes unused images, containers, networks and build cache (`docker_prune_volumes` for anonymous volumes) |
| `linux/authorized-key.yml` | authorizes an SSH key for the automation user |
| `linux/delete-path.yml` | deletes a file, a directory, or only its contents, refusing system paths |
| `linux/journald-limit.yml` | caps the journal size and vacuums old logs |
| `linux/ping.yml` | checks SSH login, Python and sudo |
| `linux/ssh-pubkey-only.yml` | allows SSH public key authentication only |
| `network/config-backup.yml` | backs up the OPNsense `config.xml` and a Brocade switch running-config |
| `network/vlan-add.yml` | adds a VLAN: OPNsense interface, DHCP, DNS and default rules; tagged on the switch trunk ports only (`vlan_apply` false = plan only) |
| `network/opnsense-automation.yml` | installs `vlan-provision` on OPNsense and limits the automation key to `semaphore-gate` (run as root) |
| `nextcloud/files-scan.yml` | rescans user files (`occ files:scan`) |
| `nextcloud/letsencrypt-cloudflare.yml` | issues or renews a Let's Encrypt certificate with the Cloudflare DNS challenge |
| `proxmox/pbs-host-backup.yml` | backs up basic node configuration files to Proxmox Backup Server |
| `proxmox/vm-create.yml` | creates a VM from a cloud-init template; from a LUKS template the disk gets its own key and is bound to Tang |
| `proxmox/vm-destroy.yml` | deletes a VM made by `vm-create.yml`, optionally destroying its client's Tang keys |
| `tang/clients.yml` | lists the Tang clients, their keys on every server and their VMs |
| `tang/server.yml` | sets up a Tang server (run as root, not from the automation user) |

## Encrypted VMs (LUKS + Tang)

Every copy of a VM disk (backups to any storage, replicas, snapshots) is only as private
as the disk itself, so the encryption lives inside the VM:

- `proxmox/files/luks-template-build.sh` builds a Debian cloud template whose root is
  LUKS2. Clones open it at first boot with a key shared by the template.
- `proxmox/vm-create.yml` clones it, re-encrypts the disk with a new key, adds a recovery
  passphrase and binds the disk to the client's Tang servers (Clevis, any one server is
  enough), then removes the template key. The VM then reboots without any key on disk.
- Every client has its own Tang keys and port (`tang/files/tang-client`). Deleting them
  (`vm-destroy.yml` with `vm_shred_client`) makes every copy of the client's disks
  unreadable, except with the recovery passphrases.
- Keep the Tang servers out of every backup job, and give the VMs a CPU type with AES-NI
  (`pve_cpu`, `x86-64-v2-AES` by default).

The generated secrets are only printed encrypted with [age](https://age-encryption.org)
(`provision_age_recipient`), so they never sit in plain text in Semaphore.

The API token (`pve_api_token_id`, privilege separation off) belongs to a user with no
password and only these rights:

| Path | Privileges |
|---|---|
| `/pool/<pve_pool>` | `VM.Allocate`, `VM.Audit`, `VM.Clone`, `VM.Config.*` (CDROM, CPU, Cloudinit, Disk, HWType, Memory, Network, Options), `VM.GuestAgent.Audit`, `VM.Migrate`, `VM.PowerMgmt` |
| `/vms/<template>` | `PVETemplateUser` (clone) |
| `/vms`, `/nodes` | `VM.Audit`, `Sys.Audit` (free VMIDs and names, task status) |
| `/storage/<pve_storage>` | `PVEDatastoreUser` |
| `/sdn/zones/localnetwork/<pve_bridge>` | `PVESDNUser` |

It can change or delete only the VMs in the pool, where `vm-create.yml` puts them.

## Conventions

- Every playbook targets `hosts: all`: the inventory and `--limit` decide where it runs.
- Defaults live in the playbook `vars`. Anything specific to an environment (addresses,
  paths, users) goes in the inventory or in a Semaphore variable group, and secrets in
  Semaphore secrets: never in this repository.

## Using it with Semaphore

1. Add this repository under **Repositories**.
2. Create the inventory and the SSH key in the **Key Store**.
3. Create a variable group with the variables the playbook needs.
4. Create a task template with the playbook path (e.g. `playbooks/docker/prune.yml`),
   then run it manually or add a schedule.

## Checks

Every push and pull request runs `ansible-lint` (see `.github/workflows/lint.yml`).
Locally:

```bash
pip install ansible-core ansible-lint
ansible-galaxy collection install -r requirements.yml
ansible-lint
```

Older playbooks (k8s, Wake-on-LAN, CPU frequency, time sync, Firefly importer, …) are
available at the `legacy-2026-10-27` tag.
