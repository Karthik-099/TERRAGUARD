# Public HTTPS is intended for a load balancer and must not be flagged.
# forbid: TG-AWS-SG-001
resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = "sg-123"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
