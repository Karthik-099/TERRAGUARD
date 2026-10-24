# forbid: TG-SEC-001, TG-SEC-002, TG-SEC-003
variable "db_password" {
  type      = string
  sensitive = true
}
resource "aws_db_instance" "db" {
  password          = var.db_password
  storage_encrypted = true
}
