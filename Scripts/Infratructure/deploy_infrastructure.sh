#!/bin/sh

cd Terraform
terraform apply -auto-approve

cd ../
ansible-playbook -i Ansible/inventory.ini Ansible/main.yml