# expect: TG-AWS-SG-001
resource "aws_security_group_rule" "all" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123"
}
