# expect: TG-NTX-PRV-001, TG-NTX-VM-001, TG-NTX-VM-002, TG-NTX-FLOW-001, TG-NTX-IMG-001, TG-NTX-NKE-001, TG-NTX-ST-001, TG-NTX-IAM-001, TG-NTX-SNMP-001, TG-NTX-SNMP-002, TG-VAL-023
provider "nutanix" {
  endpoint = "prism.example.internal"
  insecure = true
}

resource "nutanix_virtual_machine" "web" {
  name                                     = "web"
  cluster_uuid                             = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  boot_type                                = "UEFI"
  guest_customization_cloud_init_user_data = "I2Nsb3VkLWNvbmZpZwpzc2hfcHdhdXRoOiB0cnVlCnBhc3N3b3JkOiBQYXNzdzByZC0xMjMK"
}

resource "nutanix_virtual_machine_v2" "app" {
  name         = "app"
  machine_type = "Q36"
  boot_config {
    uefi_boot {
      is_secure_boot_enabled = false
    }
  }
}

resource "nutanix_network_security_rule" "web" {
  name            = "web"
  app_rule_action = "APPLY"
  app_rule_inbound_allow_list {
    peer_specification_type = "ALL"
    protocol                = "ALL"
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
        src_allow_spec                    = "ALL"
        is_all_protocol_allowed           = true
      }
    }
  }
}

resource "nutanix_image" "ubuntu" {
  name       = "ubuntu"
  source_uri = "http://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
}

resource "nutanix_images_v2" "rocky" {
  name = "rocky"
  type = "DISK_IMAGE"
  source {
    url_source {
      url                       = "https://mirror.example.com/rocky.qcow2"
      should_allow_insecure_url = true
    }
  }
}

resource "nutanix_karbon_cluster" "dev" {
  name    = "dev"
  version = "1.27.5-0"
  etcd_node_pool {
    node_os_version = "ntnx-1.6"
    num_instances   = 1
  }
  master_node_pool {
    node_os_version = "ntnx-1.6"
    num_instances   = 1
  }
}

resource "nutanix_storage_containers_v2" "scratch" {
  name               = "scratch"
  cluster_ext_id     = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  replication_factor = 1
}

resource "nutanix_directory_services_v2" "ad" {
  name           = "corp"
  url            = "ldap://dc1.corp.example.com:389"
  domain_name    = "corp.example.com"
  directory_type = "ACTIVE_DIRECTORY"
}

resource "nutanix_snmp_user_v2" "monitor" {
  cluster_ext_id = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  username       = "monitor"
  auth_type      = "MD5"
  priv_type      = "DES"
}

resource "nutanix_snmp_trap_v2" "trap" {
  cluster_ext_id   = "0005a7b8-3c1d-4b2e-9f00-0000000000aa"
  address          = "10.0.0.5"
  version          = "V2"
  community_string = "public"
}
