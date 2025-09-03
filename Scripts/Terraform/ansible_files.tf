resource "local_file" "ansible_invertory" {
  content = <<EOT
[jenkins]
${aws_instance.ecliptix_control.public_ip} ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/ecliptix-control-key.pem
EOT
  filename = "${path.module}/../Ansible/inventory.ini"
}

resource "local_file" "ansible_vars" {
  content = <<EOT
aws_region: "eu-central-1"
ecr_repo: ${aws_ecr_repository.memberships.repository_url}
ecs_cluster: ${aws_ecs_cluster.ecliptix.name}
ecs_memberships_service: ${aws_ecs_service.memberships.name}
EOT
  filename = "${path.module}/../Ansible/group_vars/all.yml"
}
