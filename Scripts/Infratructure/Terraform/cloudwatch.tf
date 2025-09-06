resource "aws_cloudwatch_log_group" "memberships" {
  name              = "/ecs/ecliptix-memberships"
  retention_in_days = 30
}
