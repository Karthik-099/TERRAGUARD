# Iterator names in dynamic blocks and for-expressions are not undeclared references.
# forbid: TG-VAL-003
variable "rules" {
  default = [{ port = 443, cidr = "10.0.0.0/8" }]
}
resource "aws_security_group" "s" {
  dynamic "ingress" {
    for_each = var.rules
    iterator = r
    content {
      from_port   = r.value.port
      to_port     = r.value.port
      protocol    = "tcp"
      cidr_blocks = [for c in [r.value.cidr] : c]
    }
  }
}
