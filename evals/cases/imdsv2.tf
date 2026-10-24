# forbid: TG-AWS-EC2-001
resource "aws_launch_template" "web" {
  metadata_options {
    http_tokens = "required"
  }
}
