# expect: TG-OS-SG-001, TG-OVH-DB-001
resource "openstack_networking_secgroup_rule_v2" "ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = "sg"
}
resource "ovh_cloud_project_database_ip_restriction" "any" {
  service_name = "svc"
  engine       = "postgresql"
  cluster_id   = "c"
  ip           = "0.0.0.0/0"
}
