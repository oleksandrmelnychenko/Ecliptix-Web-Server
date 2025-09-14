module "global" {
  source = "../../global"
}

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

module "security" {
  source   = "../../modules/security"
  
  vpc_id   = module.network.vpc_id

  alb_ports         = [5051, 8080]
  allowed_ssh_cidrs = ["0.0.0.0/0"]
  allowed_vpc_cidr  = "10.2.0.0/16"
}


module "vpc_endpoints" {
  source = "../../modules/vpc_endpoints"

  vpc_id                = module.network.vpc_id
  region                = var.aws_region
  private_subnet_ids    = module.network.private_subnets
  public_route_table_id = module.network.public_route_table_id
  endpoint_sg_id        = module.security.endpoint_sg_id

  tags = {
    project = "ecliptix"
    env     = "dev"
    region  = "eu-central-1"
  }
}

module "alb" {
  source = "../../modules/alb"

  vpc_id                = module.network.vpc_id
  public_subnet_ids     = module.network.public_subnets
  alb_sg_id             = module.security.alb_sg_id
  alb_acm_certificate_arn = var.alb_acm_certificate_arn

  project = "ecliptix"
  env     = "dev"
  tags = {
    project = "ecliptix"
    env     = "dev"
    region  = "eu-central-1"
  }
}

module "ecs_cluster" {
  source = "../../modules/ecs/ecs_cluster"

  project = "ecliptix"
  env     = "dev"
  tags = {
    project = "ecliptix"
    env     = "dev"
    region  = "eu-central-1"
  } 
}
