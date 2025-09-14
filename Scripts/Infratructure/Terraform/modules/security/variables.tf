variable "vpc_id" {
  type        = string
  description = "VPC for all security groups"
}

variable "alb_ports" {
  type    = list(number)
  default = [5051, 8080]
}

variable "allowed_ssh_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "allowed_vpc_cidr" {
  type    = string
} 
