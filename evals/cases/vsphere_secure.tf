# forbid: TG-VS-PRV-001, TG-VS-NET-001, TG-VS-VM-001, TG-VS-VM-002, TG-VS-HOST-001, TG-VS-CL-001, TG-VS-DS-001, TG-VAL-024
provider "vsphere" {
  vsphere_server = "vcenter.example.internal"
}

resource "vsphere_distributed_port_group" "app" {
  name                            = "app"
  distributed_virtual_switch_uuid = "50 1a 2b 3c"
  allow_promiscuous               = false
  allow_forged_transmits          = false
  allow_mac_changes               = false
}

variable "admin_password" {
  type      = string
  sensitive = true
}

resource "vsphere_virtual_machine" "win" {
  name                    = "win01"
  resource_pool_id        = "resgroup-1"
  firmware                = "efi"
  efi_secure_boot_enabled = true
  scsi_type               = "pvscsi"
  num_cpus                = 2
  memory                  = 4096
  guest_id                = "windows2019srv_64Guest"
  clone {
    template_uuid = "4219a1b2"
    customize {
      windows_options {
        computer_name  = "win01"
        admin_password = var.admin_password
      }
    }
  }
}

data "vsphere_host" "existing" {
  name          = "esx02.example.internal"
  datacenter_id = "datacenter-1"
}

resource "vsphere_host" "esx01" {
  hostname   = "esx01.example.internal"
  username   = "root"
  cluster    = "domain-c1"
  thumbprint = "AA:BB:CC"
  lockdown   = "normal"
}

resource "vsphere_compute_cluster" "prod" {
  name            = "prod"
  datacenter_id   = "datacenter-1"
  host_system_ids = ["host-1", "host-2"]
  ha_enabled      = true
  drs_enabled     = true
}

resource "vsphere_datastore_cluster" "prod" {
  name          = "prod-ds"
  datacenter_id = "datacenter-1"
  sdrs_enabled  = true
}
