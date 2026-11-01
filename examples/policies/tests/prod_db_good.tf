# forbid: ORG-PROD-001, ORG-TAG-001
resource "aws_db_instance" "orders" {
  multi_az                = true
  backup_retention_period = 14
  storage_encrypted       = true
  deletion_protection     = true
  tags = { env = "prod", owner = "payments", cost_center = "CC-1042" }
}
