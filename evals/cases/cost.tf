# expect: TG-COST-001, TG-COST-002, TG-COST-003
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 500
  type              = "gp2"
  encrypted         = true
}
resource "aws_instance" "legacy" {
  ami           = "ami-1"
  instance_type = "m4.large"
  metadata_options {
    http_tokens = "required"
  }
}
resource "aws_cloudwatch_log_group" "app" {
  name = "/app"
}
