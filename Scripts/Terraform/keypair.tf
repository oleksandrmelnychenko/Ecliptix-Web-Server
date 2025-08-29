resource "tls_private_key" "ecliptix_key" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "ecliptix_key" {
  key_name   = "ecliptix-control-key"
  public_key = tls_private_key.ecliptix_key.public_key_openssh
}
