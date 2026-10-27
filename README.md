# homelab automation — Semaphore + Ansible

Ansible playbooks that keep the homelab VMs, LXCs and services maintained. They run from
[Semaphore UI](https://github.com/semaphoreui/semaphore) (`cfg-ansible`, project `homelab-ops`),
which pulls this repository on every run.

## Layout

```
playbooks/
├── checkmk/     Checkmk local checks (files/ holds the check scripts)
├── docker/      Docker hosts maintenance
├── linux/       generic Debian/Ubuntu tasks (logs, SSH, cleanup, health check)
├── network/     OPNsense and switch configuration backups
├── nextcloud/   Nextcloud maintenance and its TLS certificate
└── proxmox/     Proxmox VE nodes
extras/
└── grafana-dashboards/   dashboard exports, not used by Ansible
```

Every playbook targets `hosts: all`: the Semaphore inventory and the template's **Limit**
decide where it runs. Defaults live in the playbook `vars`; anything specific to a run
(paths, users, secrets) is set in a Semaphore **variable group**, never in this repository.

## Playbooks and Semaphore templates

| Playbook | Semaphore template | Inventory · limit | Schedule |
|---|---|---|---|
| `nextcloud/files-scan.yml` | app-nextcloud-scan-user | PRODVMS · svc-ncloud | every night 01:00 |
| `nextcloud/letsencrypt-cloudflare.yml` | app-ncloud-ssl | PRODVMS · svc-ncloud | 28th of the month 10:00 |
| `proxmox/pbs-host-backup.yml` | pbs-backup-client-pve | PVE-CLUSTER | every day 10:00 |
| `docker/prune.yml` | app-docker-hard-clean-dev | PRODVMS · docker-dev | every night 02:30 |
| `docker/prune.yml` | app-docker-hard-clean-prod | PRODVMS · docker-prod | every night 02:45 |
| `linux/journald-limit.yml` | vms-log-cleanup-check-dkr | PRODVMS | 1st of the month 10:00 |
| `network/config-backup.yml` | net-config-backup | NETWORK | every night 05:15 |
| `linux/delete-path.yml` | app-delete-download-dir-dev | PRODVMS · docker-dev | manual |
| `linux/ping.yml` | vms-ping, hyperv-ping | PRODVMS, PVE-CLUSTER | manual |
| `linux/authorized-key.yml` | — | any | manual (onboarding) |
| `linux/ssh-pubkey-only.yml` | — | any | manual (new VMs) |
| `checkmk/deploy-local-check.yml` | — | any | manual |

## Access

Semaphore logs in with its own SSH key (key store: `semaphore-ssh`), authorized for the
`ansible` user on each managed host and restricted to connections from `cfg-ansible`.
On OPNsense the same key can only run `cat /conf/config.xml`; on TrueNAS it maps to the
`netbackup` user, which can only write to `spacecifs/ntw-backup`.

To add a host: create the `ansible` user with passwordless sudo, authorize the Semaphore
key (`linux/authorized-key.yml`, or by hand), add it to the inventory and run `vms-ping`.

## Checks

Every push and pull request runs `ansible-lint` (see `.github/workflows/lint.yml`).
Locally:

```bash
pip install ansible-core ansible-lint
ansible-galaxy collection install -r requirements.yml
ansible-lint
```

The playbooks removed in the October 2026 cleanup (k8s, Wake-on-LAN, CPU frequency,
time sync, Firefly importer, …) are still available at the `legacy-2026-10-27` tag.
