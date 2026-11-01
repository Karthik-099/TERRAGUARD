# TerraGuard on Google Cloud: Cloud Run with internal-only ingress. Only
# callers inside the VPC (or via Private Service Connect) can reach it, and
# only members of the allowed group can invoke it.
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

variable "project" {
  type        = string
  description = "Google Cloud project ID."
}

variable "region" {
  type        = string
  description = "Cloud Run region."
}

variable "name" {
  type        = string
  description = "Service name."
  default     = "terraguard"
}

variable "image" {
  type        = string
  description = "Image in Artifact Registry (Cloud Run cannot pull from ghcr.io directly; use a remote repository that mirrors it)."
}

variable "invoker_group" {
  type        = string
  description = "Google group allowed to use TerraGuard, e.g. group:platform@example.com."
}

resource "google_cloud_run_v2_service" "this" {
  project             = var.project
  name                = var.name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = true

  template {
    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
    containers {
      image = var.image
      args  = ["serve", "--addr", "0.0.0.0:8080"]
      ports {
        container_port = 8080
      }
      env {
        name  = "TERRAGUARD_TRUST_PROXY"
        value = "true"
      }
      resources {
        limits = { cpu = "1", memory = "1Gi" }
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  project  = var.project
  location = google_cloud_run_v2_service.this.location
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = var.invoker_group
}

output "internal_url" {
  value       = google_cloud_run_v2_service.this.uri
  description = "Service URL, reachable only from internal networks."
}
