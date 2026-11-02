# expect: TG-AWS-S3-001, TG-AWS-SG-001, TG-AWS-RDS-001
variable "acl" {
  type    = string
  default = "public-read"
}
variable "public" {
  type    = bool
  default = true
}
locals {
  admin_cidrs = ["0.0.0.0/0"]
  db_public   = var.public
}
resource "aws_s3_bucket" "b" {
  bucket = "var-resolved-bucket"
  acl    = var.acl
}
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = local.admin_cidrs
  }
}
resource "aws_db_instance" "db" {
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  publicly_accessible = local.db_public
  storage_encrypted   = true
}
