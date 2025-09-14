module "network" {
  source = "../../modules/network"

  vpc_cidr           = "10.2.0.0/24"
  availability_zones = ["eu-central-1a", "eu-central-1b", "eu-cental-1c"]
  public_cidrs       = ["10.2.0.0/27", "10.2.0.32/27", "10.2.0.64/27"]
  private_cidrs      = ["10.2.0.160/27", "10.2.0.192/27", "10.2.0.224/27"]

  endpoint_sg_id = module.security.endpoint_sg_id

  tags = {
    project = "ecliptix"
    env     = "dev"
    region  = "eu-central-1"
  }
}
