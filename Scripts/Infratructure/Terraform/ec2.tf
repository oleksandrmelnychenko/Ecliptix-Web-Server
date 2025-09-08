# ---  EC2 інстанс для ecliptix-control ---

resource "aws_instance" "ecliptix_control" {
  ami             = "ami-02003f9f0fde924ea"  
  instance_type   = "t3.medium"
  subnet_id       = aws_subnet.ecliptix_public[0].id
  key_name        = aws_key_pair.ecliptix_key.key_name
  vpc_security_group_ids = [aws_security_group.ecliptix_control_sg.id]
  
  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    delete_on_termination = true
  }
  
  tags = { Name = "ecliptix-control" }
}
