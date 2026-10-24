variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "zone_id" {
  type = string
}

variable "db_password" {
  type    = string
  default = "changeme123"
}

variable "legacy_flag" {
  type    = bool
  default = false
}
