terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = { owner = "platform" }
  }
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_s3_bucket" "data" {
  bucket = "acme-customer-data-prod"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "main" {
  identifier              = "prod-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "app"
  password                = var.db_password
  publicly_accessible     = false
  storage_encrypted       = true
  deletion_protection     = true
  backup_retention_period = 7
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }
}
