# expect: TG-AWS-S3-001
resource "aws_s3_bucket" "site" {
  bucket = "acme-site"
  acl    = "public-read"
}
