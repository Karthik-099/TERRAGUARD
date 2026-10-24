# forbid: TG-AWS-S3-001, TG-AWS-S3-002
resource "aws_s3_bucket" "b" {
  bucket = "acme-private"
}
resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
