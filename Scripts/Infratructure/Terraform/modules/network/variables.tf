variable "vpc_cidr" {
  type = string
}

variable "availability_zones" {
  type = list(string)
}

variable "public_cidrs" {
  type = list(string)
}

variable "private_cidrs" {
  type = list(string)
}

variable "endpoint_sg_id" {
  type        = string
  description = "Security group ID for VPC endpoints"
}

variable "tags"{
  type    = map(string)
  default = {}
}
