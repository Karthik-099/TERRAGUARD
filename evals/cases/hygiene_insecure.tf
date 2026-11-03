# expect: TG-TF-005, TG-TF-006, TG-TF-007, TG-TF-008
variable "name" {
  description = "Bucket name"
}
locals {
  unused_tag = "x"
}
data "aws_caller_identity" "unused" {}
resource "aws_s3_bucket" "b" {
  bucket = "${var.name}"
}
