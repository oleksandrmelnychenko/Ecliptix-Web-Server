output "ecliptix_control_public_ips" {
  value = aws_instance.ecliptix_control.public_ip
}

output "ecliptix_control_user" {
  value = "ubuntu"
}

output "ecliptix_private_key_ed25519" {
  value     = tls_private_key.ecliptix_key.private_key_openssh
  sensitive = true
}

output "alb_dns" {
  value = aws_lb.ecliptix.dns_name
}


output "ecr_repo" {
  value = aws_ecr_repository.memberships.repository_url
}

output "ecs_cluster" {
  value = aws_ecs_cluster.ecliptix.name
}

output "ecs_memberships_service" {
  value = aws_ecs_service.memberships.name
} 

# --- Files ---

resource "local_file" "ansible_invertory" {
  content = <<EOT
[jenkins]
${aws_instance.ecliptix_control.public_ip} ansible_user=ubuntu ansible_ssh_private_key_file=~./ssh/ecliptix-control-key.pem
EOT
  filename = "${path.module}/inventory.ini"
}
