# expect: TG-HPE-MIG-001, TG-HPE-LB-001, TG-HPE-LB-002, TG-HPE-METAL-001
terraform {
  required_providers {
    hpegl = {
      source  = "HPE/hpegl"
      version = "0.4.20"
    }
  }
}

data "hpegl_vmaas_cloud" "cloud" {
  name = "HPE GreenLake VMaaS Cloud"
}

resource "hpegl_vmaas_load_balancer_virtual_server" "web" {
  lb_id       = data.hpegl_vmaas_cloud.cloud.id
  name        = "web"
  vip_address = "10.11.12.13"
  vip_port    = "8080"
  pool        = 2
  type        = "http"
}

resource "hpegl_vmaas_load_balancer_profile" "client" {
  lb_id        = 1
  name         = "client-ssl"
  profile_type = "ssl-profile"
  client_profile {
    service_type = "LBClientSslProfile"
    ssl_suite    = "HIGH_COMPATIBILITY"
  }
}

resource "hpegl_metal_host" "node" {
  name          = "node1"
  image         = "ubuntu@22.04"
  machine_size  = "G2i"
  location      = "USA:Texas:AUSL2"
  networks      = ["Private"]
  ssh           = ["key-id"]
  user_data     = <<-EOT
    #cloud-config
    chpasswd:
      list: |
        root:Sup3rS3cretPw
    password: Sup3rS3cretPw
  EOT
}
