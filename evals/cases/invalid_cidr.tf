# expect: TG-VAL-004, TG-VAL-006
resource "aws_vpc" "v" {
  cidr_block = "10.0.0.300/16"
}
resource "aws_security_group_rule" "r" {
  type              = "ingress"
  from_port         = 8080
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = "sg-1"
}
