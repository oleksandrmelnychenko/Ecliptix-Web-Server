output "ecliptix_control_id" {
  value = aws_instance.ecliptix_control.id
}

output "ecliptix_control_public_ip" {
  value = aws_instance.ecliptix_control.public_ip
}

output "ecliptix_control_private_ip" {
  value = aws_instance.ecliptix_control.private_ip
}
