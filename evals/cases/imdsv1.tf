# expect: TG-AWS-EC2-001
resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
