resource "aws_cloudwatch_log_group" "memberships" {
  name              = var.memberships_logs_name
  retention_in_days = 30
}
