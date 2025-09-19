#!/bin/sh

usage() {
  echo "Usage: $0 {dev|prod}"
  exit 1
}

ENV_ARG="${1:-}"
case "${ENV_ARG}" in
  dev|prod) ;;
  *) usage ;;
esac

current_datetime=$(date +%Y-%m-%d_%H-%M-%S)
this_dir="$(cd "$(dirname "$0")" && pwd)"

# cd ../
# ansible-playbook -i Ansible/inventory.ini Ansible/main.yml -v | tee -a "Logs/${current_datetime}-log.txt"


cd Terraform/global
terraform init
terraform apply -auto-approve | tee -a "${this_dir}/Logs/${current_datetime}-log.txt"

if [ "${ENV_ARG}" = "dev" ]; then
  cd "${this_dir}/Terraform/environments/dev"
  terraform init
  terraform apply -auto-approve | tee -a "${this_dir}/Logs/${current_datetime}-log.txt"
elif [ "${ENV_ARG}" = "prod" ]; then
  cd "${this_dir}/Terraform/environments/prod"
  terraform init
  terraform apply -auto-approve | tee -a "${this_dir}/Logs/${current_datetime}-log.txt"
fi