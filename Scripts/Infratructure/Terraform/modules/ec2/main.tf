# ---  EC2 instance for ecliptix-control ---

resource "aws_instance" "ecliptix_control" {
  ami           = var.ecliptix_control_ami
  instance_type = var.ecliptix_control_instance_type
  subnet_id     = var.ecliptix_control_subnet_id
  key_name      = var.ecliptix_key_name

  vpc_security_group_ids = [var.ecliptix_control_sg_id]

  root_block_device {
    volume_size           = var.ecliptix_control_volume_size
    volume_type           = var.ecliptix_control_volume_type
    delete_on_termination = true
  }

  tags = {
    Name = "ecliptix-control"
  }
}
