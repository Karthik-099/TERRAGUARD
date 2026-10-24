# expect: TG-STATE-001, TG-TF-003
terraform {
  backend "s3" {
    bucket = "acme-tfstate"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}
resource "aws_sqs_queue" "q" {
  name = "q"
}
