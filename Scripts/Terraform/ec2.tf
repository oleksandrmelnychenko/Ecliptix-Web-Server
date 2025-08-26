# --- Два EC2 інстанси для ecliptix-control ---

resource "aws_instance" "ecliptix_control" {
  count           = 1
  ami             = "ami-02003f9f0fde924ea" # Ubuntu 24.04 LTS 
  instance_type   = "t3.medium"
  subnet_id       = aws_subnet.ecliptix_public_1a.id
  key_name        = aws_key_pair.ecliptix_key.key_name
  vpc_security_group_ids = [aws_security_group.ecliptix_control_sg.id]
  tags = { Name = "ecliptix-control-${count.index + 1}" }
}
