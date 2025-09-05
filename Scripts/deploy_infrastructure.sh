#!/bin/sh

cd Terraform
terraform apply -auto-approve

cd ../
ansible-playbook -i Ansible/inventory.ini Ansible/jenkins.yml Ansible/nginx.yml
