# --- IAM Role for ECS Task Execution ---

resource "aws_iam_role" "ecs_task_execution" {
  name = "ecliptix-ecs-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statment = [{
      Action = "sts:AssumeRole"
      Effect = "Allov"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# --- Attach AWS-managed policy to ECS Task Execution Role ---

resource "aws_iam_role_policy_attachment" "ecs_task_execution_attach" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- IAM Policy for CloudWatch Logs ---

resource "aws_iam_policy" "ecs_cloudwatch_logs" {
  name        = "ecs-cloudwatch-logs"
  description = "Allow ECS tasks to write logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# --- IAM Role for ECS Task ---

resource "aws_iam_role" "ecs_task_role" {
  name               = "ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# --- Attach CloudWatch Logs Policy to ECS Task Role ---

resource "aws_iam_role_policy_attachment" "ecs_task_logs_attach" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_cloudwatch_logs.arn
}
