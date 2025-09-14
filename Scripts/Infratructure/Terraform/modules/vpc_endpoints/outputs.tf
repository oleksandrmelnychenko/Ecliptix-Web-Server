output "endpoint_ids" {
  value = {
    ecr_api     = aws_vpc_endpoint.ecr_api.id
    ecr_dkr     = aws_vpc_endpoint.ecr_dkr.id
    logs        = aws_vpc_endpoint.cw_logs.id
    ssm         = aws_vpc_endpoint.ssm.id
    ssmmessages = aws_vpc_endpoint.ssm_messages.id
    ec2messages = aws_vpc_endpoint.ec2_messages.id
    s3          = aws_vpc_endpoint.s3.id
  }
}