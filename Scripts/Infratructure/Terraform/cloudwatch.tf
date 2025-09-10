resource "aws_cloudwatch_log_group" "memberships" {
  name              = "ecliptix-memberships-logs"
  retention_in_days = 30
}
