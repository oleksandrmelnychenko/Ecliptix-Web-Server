output "ecliptix_key" {
  value       = aws_key_pair.ecliptix_key
  description = "The name of the key pair"
}

output "ecliptix_private_key" {
  value     = tls_private_key.ecliptix_key.private_key_pem
  sensitive = true
}

output "ecliptix_private_key_path" {
  value       = local_file.ecliptix_private_key.filename
  description = "Path to the saved private key"
}
