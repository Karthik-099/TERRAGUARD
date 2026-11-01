# forbid: TG-TF-004
variable "region" {
  type        = string
  description = "AWS region to deploy into"
}
output "id" {
  value       = var.region
  description = "The region, echoed back"
}
