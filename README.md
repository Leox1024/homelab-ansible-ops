# Homelab Automation — Semaphore + Ansible

This repository contains Ansible playbooks structured by **service** or **environment**, designed to automate and maintain virtual machines and applications within a homelab infrastructure.  
It integrates with [Semaphore](https://github.com/ansible-semaphore/semaphore) for visual task execution, scheduling, and centralized SSH credential management.


## 📁 Folder Structure
```
├── debian12-playbook/     # Playbooks for base Debian 12 VM management
├── k8s-playbook/                   # Kubernetes cluster maintenance and automation
├── docker-playbook/                # Docker host setup, container updates, and cleanup
└── README.md
```

## 🛠 How to Use with Semaphore
```
1. In Semaphore:
   - Create a new Task Template
   - Use Local Repository
   - Set the playbook path (e.g. `debian12-playbook/apt-update.yml`)
2. Assign the correct Inventory, SSH key, and Variable group.
3. Run the task or schedule it.
```

## 📌 Requirements
```
- Ansible installed on the host or container
- Semaphore up and running
- VM access via SSH (key-based authentication preferred)
```

## 🖥️ Targeting hosts in playbooks

All playbooks in this repository are written with:

```yaml
hosts: all
```

To run a playbook on a specific host or group, use the Limit field in AWX/Ansible Tower templates or pass the --limit flag via CLI:
```bash
ansible-playbook playbook.yml --limit svc-ncloud
```

This approach keeps playbooks generic and reusable across different environments and inventories.
