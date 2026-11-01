# Non-production databases are out of scope for ORG-PROD-001.
# forbid: ORG-PROD-001
resource "aws_db_instance" "scratch" {
  backup_retention_period = 1
  tags = { env = "dev", owner = "payments", cost_center = "CC-1042" }
}
