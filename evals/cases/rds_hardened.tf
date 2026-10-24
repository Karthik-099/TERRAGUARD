# forbid: TG-AWS-RDS-001, TG-AWS-RDS-002, TG-AWS-RDS-003, TG-SEC-001
resource "aws_db_instance" "db" {
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  manage_master_user_password = true
  publicly_accessible         = false
  storage_encrypted           = true
  deletion_protection         = true
  backup_retention_period     = 14
}
