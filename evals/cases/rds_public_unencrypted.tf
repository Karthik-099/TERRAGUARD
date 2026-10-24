# expect: TG-AWS-RDS-001, TG-AWS-RDS-002, TG-SEC-001
resource "aws_db_instance" "db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  password            = "hunter2hunter2"
  publicly_accessible = true
}
