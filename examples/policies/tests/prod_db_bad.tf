# expect: ORG-PROD-001, ORG-TAG-001
resource "aws_db_instance" "orders" {
  multi_az                = false
  backup_retention_period = 7
  tags = { env = "prod", owner = "payments" }
}
