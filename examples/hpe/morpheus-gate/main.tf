# A Morpheus provisioning workflow that runs a TerraGuard scan before provisioning.
# Resource names, arguments and phase names are from the HPE/hpe 2.3.0 docs:
# docs/resources/morpheus_task_shell_script.md, morpheus_workflow_provisioning.md.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    hpe = {
      source  = "HPE/hpe"
      version = "2.3.0"
    }
  }
}

variable "morpheus_url" {
  type        = string
  description = "Morpheus appliance URL (https://...)."
}

variable "morpheus_access_token" {
  type        = string
  description = "Morpheus API access token."
  sensitive   = true
}

variable "terraguard_version" {
  type        = string
  description = "TerraGuard release to install; checked against its checksums.txt."
  default     = "3.2.0"
}

variable "app_dir" {
  type        = string
  description = "Directory that holds the Terraform app's code where the task runs."
}

provider "hpe" {
  morpheus {
    url          = var.morpheus_url
    access_token = var.morpheus_access_token
  }
}

resource "hpe_morpheus_task_shell_script" "terraguard_scan" {
  name           = "terraguard-scan"
  code           = "terraguard-scan"
  labels         = ["terraguard"]
  source_type    = "local"
  execute_target = "local"
  retryable      = false
  script_content = <<-EOT
    set -eu
    base="https://github.com/Karthik-099/TERRAGUARD/releases/download/v${var.terraguard_version}"
    tmp="$(mktemp -d)"
    cd "$tmp"
    curl -fsSLO "$base/terraguard_linux_amd64"
    curl -fsSLO "$base/checksums.txt"
    grep ' terraguard_linux_amd64$' checksums.txt | sha256sum -c -
    chmod 0755 terraguard_linux_amd64
    cd "${var.app_dir}"
    "$tmp/terraguard_linux_amd64" scan . --fail-on HIGH
  EOT
}

resource "hpe_morpheus_workflow_provisioning" "terraguard_gate" {
  name        = "terraguard-gate"
  description = "Scan the Terraform code with TerraGuard before provisioning"
  labels      = ["terraguard"]
  platform    = "linux"
  visibility  = "private"

  task {
    task_id    = hpe_morpheus_task_shell_script.terraguard_scan.id
    task_phase = "preProvision"
  }
}
