# expect: TG-LIN-FW-001, TG-VULTR-001
resource "linode_firewall" "fw" {
  label           = "fw"
  inbound_policy  = "ACCEPT"
  outbound_policy = "ACCEPT"
  inbound {
    label    = "ssh"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = ["0.0.0.0/0"]
  }
}
resource "vultr_firewall_rule" "rdp" {
  firewall_group_id = "abc"
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "3389"
}
