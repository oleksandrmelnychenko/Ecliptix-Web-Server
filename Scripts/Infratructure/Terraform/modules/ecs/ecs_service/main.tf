resource "aws_ecs_service" "this" { 
  name                   = "${var.project}-${var.env}-memberships"
  cluster                = var.cluster_id
  task_definition        = var.task_definition_arn
  desired_count          = var.desired_count
  launch_type            = "FARGATE"
  enable_execute_command = true

  network_configuration {
    subnets           = var.private_subnet_ids
    security_groups  = [var.ecs_sg_id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = var.load_balancers
    content {
      target_group_arn = load_balancer.value.target_group_arn
      container_name   = load_balancer.value.container_name
      container_port   = load_balancer.value.container_port
    }
  }

  lifecycle {
    ignore_changes = [task_definition]
  }
  
  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-ecs_service" })
}
