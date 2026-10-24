# expect: TG-DO-FW-001, TG-DO-SPACES-001, TG-DO-DB-001, TG-DO-DROPLET-001
resource "digitalocean_firewall" "web" {
  name = "web"
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
}
resource "digitalocean_spaces_bucket" "assets" {
  name   = "assets"
  region = "nyc3"
  acl    = "public-read"
}
resource "digitalocean_database_cluster" "pg" {
  name       = "pg"
  engine     = "pg"
  size       = "db-s-1vcpu-1gb"
  region     = "nyc1"
  node_count = 1
}
resource "digitalocean_droplet" "web" {
  image  = "ubuntu-24-04-x64"
  name   = "web"
  region = "nyc1"
  size   = "s-1vcpu-1gb"
}
