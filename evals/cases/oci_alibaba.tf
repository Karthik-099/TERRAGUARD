# expect: TG-OCI-NET-001, TG-OCI-OS-001, TG-ALI-001
resource "oci_core_security_list" "sl" {
  compartment_id = "c"
  vcn_id         = "v"
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 22
      max = 22
    }
  }
}
resource "oci_objectstorage_bucket" "b" {
  compartment_id = "c"
  name           = "b"
  namespace      = "n"
  access_type    = "ObjectRead"
}
resource "alicloud_security_group_rule" "ssh" {
  type              = "ingress"
  ip_protocol       = "tcp"
  port_range        = "22/22"
  security_group_id = "sg"
  cidr_ip           = "0.0.0.0/0"
}
