data "terraform_remote_state" "global" {
  backend = "s3"
  config = {
    bucket = "ecliptix-terraform-state"
    key    = "ecliptix-global/terraform.tfstate"
    region = "eu-central-1"
  }
}

module "iam" {
  source = "../../modules/iam"

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "keypair" {
  source = "../../modules/ec2/keypair"
  ecliptix_key_name = "ecliptix-control-key"

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "cloudwatch" {
  source = "../../modules/monitoring/cloudwatch"

  memberships_logs_name = "ecliptix-memberships-logs"

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "secrets" {
  source = "../../modules/secrets"

  memberships_secret_name = "prod/ecliptix/memberships/mssql"
}

module "network" {
  source = "../../modules/network"

  vpc_cidr           = "10.1.0.0/24"
  availability_zones = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
  public_cidrs       = ["10.1.0.0/27", "10.1.0.32/27", "10.1.0.64/27"]
  private_cidrs      = ["10.1.0.160/27", "10.1.0.192/27", "10.1.0.224/27"]

  endpoint_sg_id = module.security.endpoint_sg_id

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "subnet_group" {
  source = "../../modules/network/subnet_group"

  memberships_subnet_group_name = "prod-memberships-subnet-group"
  private_subnet_ids            = module.network.private_subnets

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "security" {
  source = "../../modules/security"

  vpc_id = module.network.vpc_id

  alb_ports         = [5051, 8080]
  allowed_ssh_cidrs = ["0.0.0.0/0"]
  allowed_vpc_cidr  = "10.2.0.0/16"

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "ecliptix_control" {
  source = "../../modules/ec2"

  ecliptix_control_subnet_id = module.network.public_subnets[0]
  ecliptix_key_name          = module.keypair.ecliptix_key.key_name
  ecliptix_control_sg_id     = module.security.control_sg_id
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
    env     = "prod"
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
  env     = "prod"

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "ecs_cluster" {
  source = "../../modules/ecs/ecs_cluster"

  project = "ecliptix"
  env     = "prod"

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "ecs_service" {
  source = "../../modules/ecs/ecs_service"

  project                 = "ecliptix"
  env                     = "prod"
  cluster_id              = module.ecs_cluster.cluster_id
  task_definition_arn     = module.ecs_task_memberships.task_definition_arn
  private_subnet_ids      = module.network.private_subnets
  ecs_sg_id               = module.security.ecs_sg_id

  load_balancers = [
    {
      target_group_arn = module.alb.memberships_grpc_tg_arn
      container_name   = "memberships"
      container_port   = "5051"
    },
    {
      target_group_arn = module.alb.memberships_http_tg_arn
      container_name   = "memberships"
      container_port   = "8080"
    }
  ]

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

resource "null_resource" "ecs_service_depends" {
  depends_on = [
    module.alb.memberships_https_listener,
    module.alb.memberships_grpc_listener
  ]
}

module "rds" {
  source = "../../modules/rds"

  mssql_secret_name        = "prod/ecliptix/memberships/mssql"
  mssql_identifier         = "prod-memberships-mssql"
  mssql_engine_version     = "15.00.4435.7.v1"
  mssql_allocated_storage  = 20
  mssql_instance_class     = "db.t3.micro"
  mssql_subnet_group_name  = module.subnet_group.mssql_subnet_group_name
  mssql_sg_id              = module.security.mssql_sg_id

  ecliptix_control_id        = module.ecliptix_control.ecliptix_control_id
  ecliptix_control_public_ip = module.ecliptix_control.ecliptix_control_public_ip
  ecliptix_private_key       = module.keypair.ecliptix_private_key

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "ecs_task_memberships" {
  source = "../../modules/ecs/ecs_task"

  family            = "ecliptix-memberships"
  cpu               = "256"
  memory            = "512"
  execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn      = module.iam.ecs_task_role_arn
  container_name     = "memberships"
  image_url          = data.terraform_remote_state.global.outputs.memberships_repository_url

  port_mappings = [
    { containerPort = 5051, protocol = "tcp" },
    { containerPort = 8080, protocol = "tcp" }
  ]

  environment = [
    { name = "DOTNET_ENVIRONMENT", value = "Production" },
    {
      name  = "ConnectionStrings__EcliptixMemberships"
      value = "Server=${module.rds.memberships_mssql_address};Database=memberships;User Id=${module.secrets.memberships_username};Password=${module.secrets.memberships_password};Encrypt=True;TrustServerCertificate=True;"
    }
  ]

  tags = {
    project = "ecliptix"
    env     = "prod"
    region  = "eu-central-1"
  }
}

module "ansible" {
  source = "../../modules/ansible"

  aws_region                 = "eu-central-1"
  control_instance_public_ip = module.ecliptix_control.ecliptix_control_public_ip
  ecr_repo                   = data.terraform_remote_state.global.outputs.memberships_repository_url
  ecs_cluster                = module.ecs_cluster.cluster_name
  ecs_memberships_service    = module.ecs_service.service_name
}
