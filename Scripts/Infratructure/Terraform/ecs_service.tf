resource "aws_ecs_service" "memberships" {
  name                    = "ecliptix-memberships"
  cluster                 = aws_ecs_cluster.ecliptix.id
  task_definition         = aws_ecs_task_definition.memberships.arn
  desired_count           = 1
  launch_type             = "FARGATE"
  enable_execute_command  = true

  network_configuration {
    subnets         = aws_subnet.ecliptix_private[*].id
    security_groups = [aws_security_group.ecs_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.memberships_http.arn
    container_name   = "memberships"
    container_port   = 8080
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.memberships_grpc.arn
    container_name   = "memberships"
    container_port   = 5051
  }

  depends_on = [
    aws_lb_listener.memberships_https,
    aws_lb_listener.memberships_grpc
  ]
}
