# forbid: TG-NTX-PRV-001, TG-NTX-VM-001, TG-NTX-VM-002, TG-NTX-FLOW-001, TG-NTX-IMG-001, TG-NTX-NKE-001, TG-NTX-ST-001, TG-NTX-IAM-001, TG-NTX-SNMP-001, TG-NTX-SNMP-002, TG-VAL-023
provider "nutanix" {
  endpoint = "prism.example.internal"
  insecure = false
}

resource "nutanix_virtual_machine" "web" {
  name                                     = "web"
  cluster_uuid                             = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  boot_type                                = "SECURE_BOOT"
  machine_type                             = "Q35"
  guest_customization_cloud_init_user_data = "I2Nsb3VkLWNvbmZpZwpzc2hfYXV0aG9yaXplZF9rZXlzOgogIC0gc3NoLWVkMjU1MTkgQUFBQUMzTnphIGV4YW1wbGUKdXNlcnM6CiAgLSBuYW1lOiBvcHMKICAgIGxvY2tfcGFzc3dkOiB0cnVlCiAgICBwYXNzd2Q6ICQ2JHJvdW5kcz00MDk2JGFiYyRoYXNoCg=="
}

resource "nutanix_virtual_machine_v2" "app" {
  name         = "app"
  machine_type = "Q35"
  boot_config {
    uefi_boot {
      is_secure_boot_enabled = true
    }
  }
}

data "nutanix_virtual_machine" "existing" {
  vm_id = "0005a7b8-3c1d-4b2e-9f00-0000000000bb"
}

resource "nutanix_network_security_rule" "web" {
  name            = "web"
  app_rule_action = "APPLY"
  app_rule_inbound_allow_list {
    peer_specification_type = "FILTER"
    filter_type             = "CATEGORIES_MATCH_ALL"
    filter_kind_list        = ["vm"]
    filter_params {
      name   = "AppTier"
      values = ["frontend"]
    }
  }
}

resource "nutanix_network_security_policy_v2" "app" {
  name  = "app"
  type  = "APPLICATION"
  state = "ENFORCE"
  rules {
    type = "APPLICATION"
    spec {
      application_rule_spec {
        secured_group_category_references = ["a1b2"]
        src_category_references           = ["c3d4"]
        service_group_references          = ["e5f6"]
      }
    }
  }
}

resource "nutanix_image" "ubuntu" {
  name       = "ubuntu"
  source_uri = "http://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
  checksum = {
    checksum_algorithm = "SHA_256"
    checksum_value     = "6d8e1b5c0a4f2e3d9c7b1a0f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d"
  }
}

resource "nutanix_images_v2" "rocky" {
  name = "rocky"
  type = "DISK_IMAGE"
  source {
    url_source {
      url = "https://mirror.example.com/rocky.qcow2"
    }
  }
}

resource "nutanix_karbon_cluster" "prod" {
  name    = "prod"
  version = "1.27.5-0"
  active_passive_config {
    external_ipv4_address = "10.0.0.20"
  }
  etcd_node_pool {
    node_os_version = "ntnx-1.6"
    num_instances   = 3
  }
  master_node_pool {
    node_os_version = "ntnx-1.6"
    num_instances   = 2
  }
}

resource "nutanix_storage_containers_v2" "data" {
  name               = "data"
  cluster_ext_id     = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  replication_factor = 2
}

resource "nutanix_directory_services_v2" "ad" {
  name           = "corp"
  url            = "ldaps://dc1.corp.example.com:636"
  domain_name    = "corp.example.com"
  directory_type = "ACTIVE_DIRECTORY"
}

resource "nutanix_snmp_user_v2" "monitor" {
  cluster_ext_id = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  username       = "monitor"
  auth_type      = "SHA256"
  priv_type      = "AES256"
}

resource "nutanix_snmp_trap_v2" "trap" {
  cluster_ext_id = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  address        = "10.0.0.5"
  version        = "V3"
  username       = "monitor"
}
