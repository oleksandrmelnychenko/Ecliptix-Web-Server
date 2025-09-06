terraform {
  required_version = ">= 1.13.0"

  backend "s3" {
    bucket         = "ecliptix-terraform-state"
    key            = "ecliptix-control/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "ecliptix-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = "eu-central-1"
}

provider "tls" {}
