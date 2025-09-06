resource "aws_ecs_task_definition" "memberships" {
  family                   = "ecliptix-memberships"
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "memberships"
      image     = "${aws_ecr_repository.memberships.repository_url}:lts"
      cpu       = 256
      memory    = 512
      essential = true
      portMappings = [
        { containerPort = 5051, protocol = "tcp" },
        { containerPort = 8080, protocol = "tcp" }
      ]
      environment = [
        { 
          name = "DOTNET_ENVIRONMENT",
          value = "Deployment"
        },
        {
          name  = "ConnectionStrings__EcliptixMemberships"
          value = "Server=${aws_db_instance.memberships_mssql.address};Database=memberships;User Id=${jsondecode(data.aws_secretsmanager_secret_version.memberships_mssql.secret_string)["username"]};Password=${jsondecode(data.aws_secretsmanager_secret_version.memberships_mssql.secret_string)["password"]};Encrypt=True;TrustServerCertificate=True;"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/ecliptix-memberships"
          "awslogs-region"        = "eu-central-1"
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}
