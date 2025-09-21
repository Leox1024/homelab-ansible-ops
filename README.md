# homelab automation — semaphore + ansible

This repo contains Ansible playbooks for different **services/environments**, in order to automate and maintain vms/lxc, services and applications within a server-infrastructure/homelab.
This repo works thanks to ansible, I prefered to integrate it with [Semaphore](https://github.com/ansible-semaphore/semaphore) in order to have a GUI.

<img width="1324" height="727" alt="image" src="https://github.com/user-attachments/assets/4b2c4996-834b-4200-8bb2-92a2f8c913c4" />

## folder structure
```
├── debian12-playbook/              # playbooks for base Debian 12 VM management
├── k8s-playbook/                   # k8s maintenance and automation (WIP)
├── docker-playbook/                # Docker host setup/container-updates/cleanup
└── README.md
```

## requirements
```
- ansible installed
- semaphore installed 
```

## how to use with semaphore
```
1. in semaphore GUI:
   - add this repo in "Repositories" tab
   - create a new Task Template -> Ansible playbook
   - set the playbook path based on this repo (e.g. `debian12-playbook/apt-update.yml`)
2. assign the correct inventory and repo and variable group (VG is used to overwrite default variable in playbook, so you have to create VG before creating this automation).
3. run the task manually or schedule it.
```

## targeting hosts in playbooks

all playbooks in this repo are written with:

```yaml
hosts: all
```

to run a playbook on a specific host or group, use the "Limit" field during ansible-playbook setup or pass the --limit flag via CLI:
```bash
ansible-playbook playbook.yml --limit svc-ncloud
```
