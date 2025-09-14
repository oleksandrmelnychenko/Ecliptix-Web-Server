resource "aws_ecs_cluster" "this" {
  name = "${var.project}-${var.env}-ecs-cluster"
  tags = merge(var.tags, { Name = "${var.project}-${var.env}-ecs-cluster" })
}
