provider "aws" {
  region = "var.aws_region"
}

provider "tls" { }

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}
