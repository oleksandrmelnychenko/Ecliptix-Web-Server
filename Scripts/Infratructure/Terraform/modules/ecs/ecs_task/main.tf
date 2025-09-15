resource "aws_ecs_task_definition" "this" {
  family                   = var.family
  cpu                      = var.cpu
  memory                  = var.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]

  execution_role_arn = var.execution_role_arn
  task_role_arn      = var.task_role_arn

  container_definitions = jsonencode([
    {
      name      = var.container_name
      image     = "${var.image_url}:lts"
      cpu       = var.cpu
      memory    = var.memory
      essential = true

      portMappings = var.port_mappings

      enviroment = var.environment
    }
  ])
}
