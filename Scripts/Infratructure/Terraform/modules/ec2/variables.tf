variable "ecliptix_control_ami" {
  type        = string
  description = "AMI ID for the ecliptix-control instance"
  default     = "ami-02003f9f0fde924ea"
}

variable "ecliptix_control_instance_type" {
  type        = string
  description = "Instance type for ecliptix-control"
  default     = "t3.micro"
}

variable "ecliptix_control_subnet_id" {
  type        = string
  description = "Subnet ID for ecliptix-control"
}

variable "ecliptix_key_name" {
  type        = string
  description = "Key pair name for ecliptix-control"
}

variable "ecliptix_control_sg_id" {
  type        = string
  description = "Security Group ID for ecliptix-control"
}

variable "ecliptix_control_volume_size" {
  type        = number
  description = "Root volume size for ecliptix-control"
  default     = 30
}

variable "ecliptix_control_volume_type" {
  type        = string
  description = "Root volume type for ecliptix-control"
  default     = "gp3"
}
