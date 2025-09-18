resource "aws_ecs_cluster" "this" {
  name = "${var.project}-${var.env}-ecs-cluster"
  tags = merge(var.tags, { Name = "${var.tags["project"]}-${var.tags["env"]}-ecs-cluster" })
}
