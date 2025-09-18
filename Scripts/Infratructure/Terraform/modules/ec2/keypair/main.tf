resource "tls_private_key" "ecliptix_key" {
  algorithm = var.algorithm
}

resource "aws_key_pair" "ecliptix_key" {
  key_name   = var.ecliptix_key_name
  public_key = tls_private_key.ecliptix_key.public_key_openssh
}

resource "local_file" "ecliptix_private_key" {
  content              = tls_private_key.ecliptix_key.private_key_openssh
  filename             = pathexpand("~/.ssh/ecliptix-${var.env}-control-key.pem")
  file_permission      = "0600"
  directory_permission = "0700"
}
