# expect: TG-AWS-LAMBDA-002, TG-AWS-CDN-001, TG-AWS-MSG-001, TG-AWS-ECR-001, TG-AWS-CACHE-001, TG-AWS-VPC-001
resource "aws_lambda_function" "old" {
  function_name = "old"
  runtime       = "nodejs16.x"
  handler       = "index.handler"
  role          = "arn:aws:iam::1:role/x"
}
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
  viewer_certificate {
    minimum_protocol_version = "TLSv1"
  }
}
resource "aws_sqs_queue" "q" {
  sqs_managed_sse_enabled = false
}
resource "aws_ecr_repository" "r" {
  name = "app"
}
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "r"
  description          = "r"
}
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
