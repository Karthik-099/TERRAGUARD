# Intentionally vulnerable demo project. Every block here maps to a real-world
# incident pattern; TerraGuard should flag all of them.

provider "aws" {
  region = "us-east-1"
}

module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git"
  name   = "demo"
}

resource "aws_s3_bucket" "Customer_Data" {
  bucket = "Customer_Data_Prod"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket              = aws_s3_bucket.Customer_Data.id
  block_public_acls   = false
  block_public_policy = false
}

resource "aws_security_group" "db" {
  name   = "db-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.1/16"]
  }
}

resource "aws_db_instance" "main" {
  identifier             = "prod-db"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "SuperSecret123!"
  publicly_accessible    = true
  storage_encrypted      = false
  backup_retention_period = 0
  vpc_security_group_ids = [aws_security_group.db.id]
}

resource "aws_iam_role" "lambda" {
  name = "lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_lambda_function" "api" {
  function_name = "public-api"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "app.zip"
}

resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "NONE"
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = var.instance_type

  root_block_device {
    encrypted = false
  }
}

resource "aws_kms_key" "app" {
  description = "app key"
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  s3_bucket_name = aws_s3_bucket.Customer_Data.id
}

resource "cloudflare_zone_settings_override" "site" {
  zone_id = var.zone_id
  settings {
    ssl             = "flexible"
    min_tls_version = "1.0"
  }
}

output "db_endpoint" {
  value = aws_db_instance.primary.endpoint
}
