# path: examples/resources/hpegl_vmaas_network/resource.tf
# forbid: TG-VAL-004
# hpegl_vmaas_network takes the gateway CIDR, so host bits are expected.
resource "hpegl_vmaas_network" "net" {
  name     = "net"
  scope_id = "zone"
  cidr     = "10.100.0.1/24"
}
