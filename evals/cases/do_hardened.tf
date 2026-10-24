# forbid: TG-DO-FW-001, TG-DO-SPACES-001, TG-DO-DB-001, TG-DO-DROPLET-001
resource "digitalocean_firewall" "web" {
  name = "web"
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0"]
  }
}
resource "digitalocean_database_cluster" "pg" {
  name   = "pg"
  engine = "pg"
}
resource "digitalocean_database_firewall" "pg" {
  cluster_id = digitalocean_database_cluster.pg.id
  rule {
    type  = "tag"
    value = "app"
  }
}
resource "digitalocean_droplet" "web" {
  image    = "ubuntu-24-04-x64"
  ssh_keys = [123]
}
