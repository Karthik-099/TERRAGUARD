# expect: ORG-EC2-001
resource "aws_instance" "batch" {
  ami           = "ami-1"
  instance_type = "m5.large"
  tags = { owner = "payments", cost_center = "CC-1042" }
}
