---
- name: Restart a system service
  hosts: all
  become: true

  vars:
    service_name: "sshd" 

  tasks:
    - name: "Restart the {{ service_name }} service"
      ansible.builtin.systemd:
        name: "{{ service_name }}"
        state: restarted
