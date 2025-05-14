# Homelab Automation — Semaphore + Ansible

This repo contains Ansible playbooks for different **services/environments**, designed to automate and maintain vms, services and applications within a server infrastructure.
This repo works thanks to ansible, I prefered to integrate it with [Semaphore](https://github.com/ansible-semaphore/semaphore) in order to have a GUI.

## Folder Structure
```
├── debian12-playbook/              # Playbooks for base Debian 12 VM management
├── k8s-playbook/                   # Kubernetes cluster maintenance and automation
├── docker-playbook/                # Docker host setup, container updates, and cleanup
└── README.md
```

## Requirements
```
- Ansible installed on the host or container
- Semaphore up and running
- VM access via SSH (key-based authentication preferred)
```

## How to use with Semaphore
```
1. In Semaphore:
   - Add this repo in "Repositories" tab
   - Create a new Task Template -> Ansible playbook
   - Set the playbook path (e.g. `debian12-playbook/apt-update.yml`)
2. Assign the correct inventory, SSH key, and variable group (VG is used to overwrite default variable in playbook).
3. Run the task or schedule it.
```

## Targeting hosts in playbooks

All playbooks in this repository are written with:

```yaml
hosts: all
```

To run a playbook on a specific host or group, use the Limit field during ansible-playbook setup or pass the --limit flag via CLI:
```bash
ansible-playbook playbook.yml --limit svc-ncloud
```

This approach keeps playbooks generic and reusable across different environments and inventories.
