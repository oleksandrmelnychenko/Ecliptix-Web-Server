output "ecliptix_control_public_ips" {
  value = aws_instance.ecliptix_control[*].public_ip
}

output "ecliptix_private_key_ed25519" {
  value     = tls_private_key.ecliptix_key.private_key_openssh
  sensitive = true
}

output "alb_dns" {
  value = aws_lb.ecliptix.dns_name
}
