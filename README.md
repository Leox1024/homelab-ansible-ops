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
└── proxmox/     Proxmox VE nodes
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
| `nextcloud/files-scan.yml` | rescans user files (`occ files:scan`) |
| `nextcloud/letsencrypt-cloudflare.yml` | issues or renews a Let's Encrypt certificate with the Cloudflare DNS challenge |
| `proxmox/pbs-host-backup.yml` | backs up basic node configuration files to Proxmox Backup Server |

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
