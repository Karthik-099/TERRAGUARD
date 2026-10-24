# expect: TG-AWS-IAM-001, TG-AWS-IAM-002
data "aws_iam_policy_document" "bad" {
  statement {
    actions   = ["iam:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}
