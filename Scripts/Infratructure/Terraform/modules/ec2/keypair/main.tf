resource "tls_private_key" "ecliptix_key" {
  algorithm = var.algorithm
}

resource "aws_key_pair" "ecliptix_key" {
  key_name   = var.ecliptix_key_name
  public_key = tls_private_key.ecliptix_key.public_key_openssh
}