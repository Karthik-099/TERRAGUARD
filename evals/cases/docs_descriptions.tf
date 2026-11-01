# expect: TG-TF-004
variable "region" {
  type = string
}
output "id" {
  value = var.region
}
