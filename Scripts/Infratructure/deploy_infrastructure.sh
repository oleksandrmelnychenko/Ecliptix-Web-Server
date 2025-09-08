#!/bin/sh

current_datetime=$(date +%Y-%m-%d_%H-%M-%S)

cd Terraform
terraform apply -auto-approve | tee "../Logs/${current_datetime}-log.txt"

cd ../
ansible-playbook -i Ansible/inventory.ini Ansible/main.yml -v | tee -a "Logs/${current_datetime}-log.txt"