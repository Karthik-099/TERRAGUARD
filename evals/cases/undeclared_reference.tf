# expect: TG-VAL-003
resource "aws_instance" "web" {
  ami                    = "ami-123"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [var.sg_id]
}
