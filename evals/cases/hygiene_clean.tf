# forbid: TG-TF-005, TG-TF-006, TG-TF-007, TG-TF-008
variable "name" {
  description = "Bucket name"
  type        = string
}
locals {
  prefix = "acme"
}
data "aws_caller_identity" "me" {}
resource "aws_s3_bucket" "b" {
  bucket = "${local.prefix}-${var.name}-${data.aws_caller_identity.me.account_id}"
}
