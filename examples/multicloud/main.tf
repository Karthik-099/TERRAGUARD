# Multi-cloud demo: the same mistakes show up on every provider.
terraform {
  required_version = ">= 1.6"
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.40" }
    hcloud       = { source = "hetznercloud/hcloud", version = "~> 1.48" }
    openstack    = { source = "terraform-provider-openstack/openstack", version = "~> 2.1" }
    oci          = { source = "oracle/oci", version = "~> 6.0" }
    kubernetes   = { source = "hashicorp/kubernetes", version = "~> 2.32" }
    helm         = { source = "hashicorp/helm", version = "~> 2.15" }
    cloudflare   = { source = "cloudflare/cloudflare", version = "~> 5.0" }
  }
  backend "s3" {
    bucket = "acme-tfstate"
    key    = "multicloud/terraform.tfstate"
    region = "eu-west-1"
  }
}

# DigitalOcean: SSH open to the world, public Space, database with no trusted sources
resource "digitalocean_firewall" "web" {
  name = "web"
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_spaces_bucket" "backups" {
  name   = "acme-backups"
  region = "fra1"
  acl    = "public-read"
}

resource "digitalocean_database_cluster" "pg" {
  name       = "pg"
  engine     = "pg"
  version    = "16"
  size       = "db-s-1vcpu-1gb"
  region     = "fra1"
  node_count = 1
}

# Hetzner: firewall allowing every port, and a server with no firewall at all
resource "hcloud_firewall" "open" {
  name = "open"
  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "any"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "app" {
  name        = "app"
  server_type = "cx22"
  image       = "ubuntu-24.04"
  location    = "nbg1"
}

# OVHcloud Public Cloud (OpenStack): Postgres port open to the internet
resource "openstack_networking_secgroup_rule_v2" "pg" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5432
  port_range_max    = 5432
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = "sg-123"
}

# Oracle Cloud: public bucket
resource "oci_objectstorage_bucket" "exports" {
  compartment_id = "ocid1.compartment.oc1..example"
  name           = "exports"
  namespace      = "acme"
  access_type    = "ObjectRead"
}

# Kubernetes: privileged pod on the host network with a mutable image
resource "kubernetes_deployment_v1" "agent" {
  metadata {
    name = "agent"
  }
  spec {
    replicas = 1
    selector {
      match_labels = { app = "agent" }
    }
    template {
      metadata {
        labels = { app = "agent" }
      }
      spec {
        host_network = true
        container {
          name  = "agent"
          image = "acme/agent:latest"
          security_context {
            privileged = true
          }
        }
      }
    }
  }
}

resource "helm_release" "ingress" {
  name       = "ingress"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
}

# Cloudflare DNS: hardcoded CNAME to a deletable Heroku app (subdomain takeover)
resource "cloudflare_dns_record" "status" {
  zone_id = "023e105f4ecef8ad9ca31a8372d0c353"
  name    = "status"
  type    = "CNAME"
  content = "acme-status.herokuapp.com"
  proxied = true
  ttl     = 1
}
