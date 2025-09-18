module "ecr" {
  source = "../modules/ecr"
  
  memberships_repo_name = "ecliptix/memberships"

  tags = {
    project = "ecliptix"
    env     = "global"
    region  = "eu-central-1"
  }
}

module "iam" {
  source = "../modules/iam"

  tags = {
    project = "ecliptix"
    env     = "global"
    region  = "eu-central-1"
  }
}