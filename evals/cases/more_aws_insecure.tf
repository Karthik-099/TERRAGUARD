# expect: TG-AWS-RDS-004, TG-AWS-RDS-005, TG-AWS-DOCDB-001, TG-AWS-NEPTUNE-001, TG-AWS-MQ-001, TG-AWS-DMS-001, TG-AWS-SAGEMAKER-001, TG-AWS-KINESIS-001, TG-AWS-MSK-001, TG-AWS-OS-001, TG-AWS-IAM-002, TG-AWS-IAM-006, TG-AWS-IAM-007, TG-AWS-IAM-008, TG-AWS-LAMBDA-003, TG-AWS-CT-002, TG-AWS-GD-001, TG-AWS-EC2-002, TG-AWS-EC2-003, TG-AWS-SG-002, TG-AWS-NACL-001, TG-AWS-APIGW-002, TG-AWS-LB-003, TG-AWS-CODEBUILD-001, TG-AWS-SSM-001, TG-AWS-CDN-002
resource "aws_db_instance" "db" {
  engine            = "postgres"
  instance_class    = "db.t4g.micro"
  storage_encrypted = true
}
resource "aws_db_snapshot" "s" {
  db_instance_identifier = "db"
  db_snapshot_identifier = "s"
  shared_accounts        = ["all"]
}
resource "aws_docdb_cluster" "d" {
  cluster_identifier = "d"
}
resource "aws_neptune_cluster" "n" {
  cluster_identifier = "n"
}
resource "aws_mq_broker" "mq" {
  broker_name         = "mq"
  publicly_accessible = true
}
resource "aws_dms_replication_instance" "dms" {
  replication_instance_id = "dms"
  publicly_accessible     = true
}
resource "aws_sagemaker_notebook_instance" "nb" {
  name     = "nb"
  role_arn = "arn:aws:iam::1:role/sm"
}
resource "aws_kinesis_stream" "k" {
  name = "k"
}
resource "aws_msk_cluster" "m" {
  cluster_name = "m"
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS_PLAINTEXT"
    }
  }
}
resource "aws_opensearch_domain" "os" {
  domain_name     = "os"
  access_policies = jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "es:*", Resource = "*" }] })
}
resource "aws_iam_policy" "esc" {
  name   = "esc"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["iam:PassRole", "ec2:RunInstances"], Resource = "*" }] })
}
resource "aws_iam_role" "gha" {
  name = "gha"
  assume_role_policy = jsonencode({ Statement = [{
    Effect    = "Allow"
    Action    = "sts:AssumeRoleWithWebIdentity"
    Principal = { Federated = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" }
    Condition = { StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" } }
  }] })
}
resource "aws_iam_account_password_policy" "p" {
  minimum_password_length = 8
}
resource "aws_lambda_permission" "sns" {
  function_name = "f"
  action        = "lambda:InvokeFunction"
  principal     = "sns.amazonaws.com"
}
resource "aws_cloudtrail" "t" {
  name           = "t"
  s3_bucket_name = "b"
  enable_logging = false
}
resource "aws_guardduty_detector" "g" {
  enable = false
}
resource "aws_ami_launch_permission" "pub" {
  image_id = "ami-1"
  group    = "all"
}
resource "aws_instance" "web" {
  ami                         = "ami-1"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  metadata_options {
    http_tokens = "required"
  }
}
resource "aws_default_security_group" "default" {
  vpc_id = "vpc-1"
  ingress {
    protocol  = "-1"
    self      = true
    from_port = 0
    to_port   = 0
  }
}
resource "aws_network_acl_rule" "ssh" {
  network_acl_id = "acl-1"
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}
resource "aws_api_gateway_stage" "s" {
  stage_name    = "prod"
  rest_api_id   = "a"
  deployment_id = "d"
}
resource "aws_lb" "web" {
  name                       = "web"
  drop_invalid_header_fields = true
}
resource "aws_codebuild_project" "cb" {
  name = "cb"
  artifacts {
    type                = "S3"
    encryption_disabled = true
  }
}
resource "aws_ssm_parameter" "db_password" {
  name  = "/app/db_password"
  type  = "String"
  value = var.db_password
}
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "origin.example.com"
    origin_id   = "o"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1"]
    }
  }
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
  viewer_certificate {
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
variable "db_password" {
  description = "pw"
  type        = string
  sensitive   = true
}
