resource "local_file" "ansible_inventory" {
  content = <<EOT
[jenkins]
${var.control_instance_public_ip} ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/ecliptix-control-key.pem
EOT
  filename = "${path.module}/../../../Ansible/inventory.ini"
}

resource "local_file" "ansible_vars" {
  content = <<EOT
aws_region: "${var.aws_region}"
ecr_repo: ${var.ecr_repo}
ecs_cluster: ${var.ecs_cluster}
ecs_memberships_service: ${var.ecs_memberships_service}
EOT
  filename = "${path.module}/../../../Ansible/group_vars/all.yml"
}
