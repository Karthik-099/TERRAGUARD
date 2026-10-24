# A scoped policy that references another resource must stay clean.
# forbid: TG-AWS-IAM-001
resource "aws_s3_bucket" "b" {
  bucket = "acme-data"
}
resource "aws_iam_policy" "read" {
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.b.arn}/*" }]
  })
}
