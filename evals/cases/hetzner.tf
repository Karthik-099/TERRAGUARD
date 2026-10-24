# expect: TG-HZ-FW-001, TG-HZ-SRV-001
resource "hcloud_firewall" "fw" {
  name = "fw"
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "any"
    source_ips = ["0.0.0.0/0"]
  }
}
resource "hcloud_server" "app" {
  name        = "app"
  server_type = "cx22"
  image       = "ubuntu-24.04"
}
