#!/bin/sh

current_datetime=$(date +%Y-%m-%d_%H-%M-%S)

# cd ../
# ansible-playbook -i Ansible/inventory.ini Ansible/main.yml -v | tee -a "Logs/${current_datetime}-log.txt"


cd Terraform/global
terraform init
terraform apply -auto-approve | tee -a "../../Logs/${current_datetime}-log.txt"

cd ../enviroments/dev
terraform init  
terraform apply -auto-approve | tee -a "../../../Logs/${current_datetime}-log.txt"

cd ../enviroments/prod
terraform init
terraform apply -auto-approve | tee -a "../../../Logs/${current_datetime}-log.txt"