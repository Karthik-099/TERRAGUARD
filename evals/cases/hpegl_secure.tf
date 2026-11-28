# forbid: TG-HPE-LB-001, TG-HPE-LB-002, TG-HPE-METAL-001, TG-VAL-026
terraform {
  required_providers {
    hpegl = {
      source  = "HPE/hpegl"
      version = "0.4.20"
    }
  }
}

resource "hpegl_vmaas_load_balancer_virtual_server" "redirect" {
  lb_id       = 1
  name        = "redirect"
  vip_address = "10.11.12.13"
  vip_port    = "80"
  pool        = 2
  type        = "http"
}

resource "hpegl_metal_host" "node" {
  name         = "node1"
  image        = "ubuntu@22.04"
  machine_size = "G2i"
  location     = "USA:Texas:AUSL2"
  networks     = ["Private"]
  ssh          = ["key-id"]
  user_data    = <<-EOT
    #cloud-config
    package_upgrade: true
  EOT
}
