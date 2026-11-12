# forbid: TG-SECRET-013, TG-SECRET-014, TG-SECRET-001
variable "nutanix_password" {
  type      = string
  sensitive = true
}

provider "nutanix" {
  username = "admin"
  password = var.nutanix_password
  endpoint = "10.0.0.10"
}

resource "aws_db_instance" "db" {
  identifier                  = "app"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  username                    = "app"
  manage_master_user_password = true
}

# terraguard:ignore TG-SECRET-014
locals { fixture_token = "Hn4cW8qZ2rTj6LmX9vBd" }
