# TerraGuard on AWS: ECS Fargate in private subnets behind an internal HTTPS
# load balancer. Reachable only from inside the VPC (or over VPN/Direct Connect).
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "name" {
  type        = string
  description = "Name prefix for all resources."
  default     = "terraguard"
}

variable "vpc_id" {
  type        = string
  description = "VPC to deploy into."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for the tasks and the internal load balancer (at least two AZs)."
}

variable "allowed_cidrs" {
  type        = list(string)
  description = "Internal networks allowed to reach TerraGuard, e.g. your VPC and VPN ranges."
}

variable "certificate_arn" {
  type        = string
  description = "ACM certificate for the internal HTTPS listener."
}

variable "image" {
  type        = string
  description = "Container image. Mirror it into ECR for fully private pulls."
  default     = "ghcr.io/karthik-099/terraguard:latest"
}

variable "ai_key_parameter_arn" {
  type        = string
  description = "Optional SSM SecureString holding an AI key (empty = no AI, or a local model)."
  default     = ""
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = 90
}

resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ecs-tasks.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "read_ai_key" {
  count = var.ai_key_parameter_arn == "" ? 0 : 1
  role  = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["ssm:GetParameters"], Resource = var.ai_key_parameter_arn }]
  })
}

resource "aws_security_group" "lb" {
  name   = "${var.name}-lb"
  vpc_id = var.vpc_id
  ingress {
    description = "HTTPS from internal networks only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
  egress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
}

resource "aws_security_group" "task" {
  name   = "${var.name}-task"
  vpc_id = var.vpc_id
  ingress {
    description     = "Only from the internal load balancer"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }
  egress {
    description = "Image pulls and optional AI endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "this" {
  name                       = var.name
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = var.private_subnet_ids
  security_groups            = [aws_security_group.lb.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "this" {
  name        = var.name
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  health_check {
    path = "/healthz"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  container_definitions = jsonencode([{
    name                   = "terraguard"
    image                  = var.image
    command                = ["serve", "--addr", "0.0.0.0:8080"]
    readonlyRootFilesystem = true
    portMappings           = [{ containerPort = 8080 }]
    environment            = [{ name = "TERRAGUARD_TRUST_PROXY", value = "true" }]
    secrets                = var.ai_key_parameter_arn == "" ? [] : [{ name = "GROQ_API_KEY", valueFrom = var.ai_key_parameter_arn }]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { awslogs-group = aws_cloudwatch_log_group.this.name, awslogs-region = data.aws_region.current.name, awslogs-stream-prefix = "terraguard" }
    }
  }])
}

data "aws_region" "current" {}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 2
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "terraguard"
    container_port   = 8080
  }
}

output "internal_url" {
  value       = "https://${aws_lb.this.dns_name}"
  description = "Internal URL; point a private DNS record at it."
}
