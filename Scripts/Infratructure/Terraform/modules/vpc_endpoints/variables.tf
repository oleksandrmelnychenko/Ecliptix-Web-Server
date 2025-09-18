variable "vpc_id" {
  type        = string
  description = "VPC id"
}

variable "region" {
  type        = string
  description = "AWS region (eu-central-1)"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet ids for interface endpoints"
}

variable "public_route_table_id" {
  type        = string
  description = "Public route table id for S3 gateway endpoint"
}

variable "endpoint_sg_id" {
  type        = string
  description = "Security group id, for use Interface endpoints"
}

variable "tags" {
  type    = map(string)
  default = {}
}
