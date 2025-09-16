# --- ECR API ---
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.ecr.api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [var.endpoint_sg_id]

  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-ecr-api-endpoint" })
}

# --- ECR DKR ---
resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.ecr.dkr"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [var.endpoint_sg_id]

  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-ecr-dkr-endpoint" })
}

# --- CloudWatch Logs ---

resource "aws_vpc_endpoint" "cw_logs" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.logs"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [var.endpoint_sg_id]

  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-logs-endpoint" })
}

# --- SSM ---

resource "aws_vpc_endpoint" "ssm" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [var.endpoint_sg_id]

  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-ssm-endpoint" })
}

# --- SSM Messages ---

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.ssmmessages"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [var.endpoint_sg_id]

  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-ssmmessages-endpoint" })
}

# --- EC2 Messages ---

resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.ec2messages"
  vpc_endpoint_type = "Interface"
  subnet_ids        = var.private_subnet_ids
  security_group_ids = [var.endpoint_sg_id]

  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-ec2messages-endpoint" })
}

# --- S3 (Gateway) ---

resource "aws_vpc_endpoint" "s3" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type  = "Gateway"
  route_table_ids    = [var.public_route_table_id]

  tags = merge(var.tags, { Name = "${lookup(var.tags, "project", "proj")}-s3-endpoint" })
}
