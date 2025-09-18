terraform {
  backend "s3" {
    bucket         = "ecliptix-terraform-state"
    key            = "ecliptix-dev/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "ecliptix-terraform-locks"
    encrypt        = true
  }
}
