# forbid: TG-AWS-RDS-004, TG-AWS-RDS-005, TG-AWS-DOCDB-001, TG-AWS-NEPTUNE-001, TG-AWS-MQ-001, TG-AWS-DMS-001, TG-AWS-SAGEMAKER-001, TG-AWS-KINESIS-001, TG-AWS-MSK-001, TG-AWS-OS-001, TG-AWS-IAM-002, TG-AWS-IAM-006, TG-AWS-IAM-007, TG-AWS-IAM-008, TG-AWS-LAMBDA-003, TG-AWS-CT-002, TG-AWS-GD-001, TG-AWS-EC2-002, TG-AWS-EC2-003, TG-AWS-SG-002, TG-AWS-NACL-001, TG-AWS-APIGW-002, TG-AWS-LB-003, TG-AWS-CODEBUILD-001, TG-AWS-SSM-001, TG-AWS-CDN-002
resource "aws_db_instance" "db" {
  engine                              = "postgres"
  instance_class                      = "db.t4g.micro"
  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}
resource "aws_db_snapshot" "s" {
  db_instance_identifier = "db"
  db_snapshot_identifier = "s"
  shared_accounts        = ["123456789012"]
}
resource "aws_docdb_cluster" "d" {
  cluster_identifier = "d"
  storage_encrypted  = true
}
resource "aws_neptune_cluster" "n" {
  cluster_identifier = "n"
  storage_encrypted  = true
}
resource "aws_mq_broker" "mq" {
  broker_name         = "mq"
  publicly_accessible = false
}
resource "aws_dms_replication_instance" "dms" {
  replication_instance_id = "dms"
  publicly_accessible     = false
}
resource "aws_sagemaker_notebook_instance" "nb" {
  name                   = "nb"
  role_arn               = "arn:aws:iam::1:role/sm"
  direct_internet_access = "Disabled"
  root_access            = "Disabled"
}
resource "aws_kinesis_stream" "k" {
  name            = "k"
  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"
}
resource "aws_msk_cluster" "m" {
  cluster_name = "m"
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}
resource "aws_opensearch_domain" "os" {
  domain_name = "os"
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
  }
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  vpc_options {
    subnet_ids = ["subnet-1"]
  }
}
resource "aws_iam_policy" "ok" {
  name   = "ok"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["iam:PassRole"], Resource = "arn:aws:iam::1:role/app" }] })
}
resource "aws_iam_role" "gha" {
  name = "gha"
  assume_role_policy = jsonencode({ Statement = [{
    Effect    = "Allow"
    Action    = "sts:AssumeRoleWithWebIdentity"
    Principal = { Federated = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com" }
    Condition = { StringLike = { "token.actions.githubusercontent.com:sub" = "repo:acme/infra:ref:refs/heads/main" } }
  }] })
}
resource "aws_iam_account_password_policy" "p" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  password_reuse_prevention      = 24
}
resource "aws_lambda_permission" "sns" {
  function_name = "f"
  action        = "lambda:InvokeFunction"
  principal     = "sns.amazonaws.com"
  source_arn    = "arn:aws:sns:eu-west-1:1:topic"
}
resource "aws_cloudtrail" "t" {
  name           = "t"
  s3_bucket_name = "b"
  kms_key_id     = "arn:aws:kms:eu-west-1:1:key/k"
}
resource "aws_guardduty_detector" "g" {
  enable = true
}
resource "aws_instance" "app" {
  ami           = "ami-1"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}
resource "aws_default_security_group" "default" {
  vpc_id = "vpc-1"
}
resource "aws_network_acl_rule" "https" {
  network_acl_id = "acl-1"
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}
resource "aws_api_gateway_stage" "s" {
  stage_name    = "prod"
  rest_api_id   = "a"
  deployment_id = "d"
  access_log_settings {
    destination_arn = "arn:aws:logs:eu-west-1:1:log-group:api"
    format          = "$context.requestId"
  }
}
resource "aws_lb" "web" {
  name                       = "web"
  drop_invalid_header_fields = true
  access_logs {
    bucket  = "logs"
    enabled = true
  }
}
resource "aws_codebuild_project" "cb" {
  name = "cb"
  artifacts {
    type = "S3"
  }
}
resource "aws_ssm_parameter" "db_password" {
  name  = "/app/db_password"
  type  = "SecureString"
  value = var.db_password
}
resource "aws_ssm_parameter" "region" {
  name  = "/app/region"
  type  = "String"
  value = "eu-west-1"
}
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "origin.example.com"
    origin_id   = "o"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
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
