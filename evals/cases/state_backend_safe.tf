# forbid: TG-STATE-001, TG-STATE-003, TG-TF-003
terraform {
  required_version = ">= 1.10"
  backend "s3" {
    bucket       = "acme-tfstate"
    key          = "prod/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
resource "aws_sqs_queue" "q" {
  name = "q"
}
