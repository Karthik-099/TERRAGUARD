# expect: TG-VS-PRV-001, TG-VS-NET-001, TG-VS-VM-001, TG-VS-VM-002, TG-VS-HOST-001, TG-VS-CL-001, TG-VS-DS-001, TG-VAL-024
provider "vsphere" {
  vsphere_server       = "vcenter.example.internal"
  allow_unverified_ssl = true
}

resource "vsphere_distributed_port_group" "dmz" {
  name                            = "dmz"
  distributed_virtual_switch_uuid = "50 1a 2b 3c"
  allow_promiscuous               = true
  allow_forged_transmits          = true
  allow_mac_changes               = true
}

resource "vsphere_virtual_machine" "win" {
  name             = "win01"
  resource_pool_id = "resgroup-1"
  firmware         = "efi"
  scsi_type        = "lsi"
  num_cpus         = 2
  memory           = 4096
  guest_id         = "windows2019srv_64Guest"
  clone {
    template_uuid = "4219a1b2"
    customize {
      windows_sysprep_text = <<-XML
        <unattend><settings pass="oobeSystem"><component name="Microsoft-Windows-Shell-Setup">
        <UserAccounts><AdministratorPassword><Value>Winter2024!</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
        </component></settings></unattend>
      XML
    }
  }
}

resource "vsphere_host" "esx01" {
  hostname   = "esx01.example.internal"
  username   = "root"
  cluster    = "domain-c1"
  thumbprint = "AA:BB:CC"
}

resource "vsphere_compute_cluster" "prod" {
  name            = "prod"
  datacenter_id   = "datacenter-1"
  host_system_ids = ["host-1", "host-2"]
}

resource "vsphere_datastore_cluster" "prod" {
  name          = "prod-ds"
  datacenter_id = "datacenter-1"
}
