provider "hpegl" {
  iam_version     = "glcs"
  iam_service_url = var.iam_service_url
  vmaas {
    location   = "HPE-Data-Center"
    space_name = "my-space"
    broker_url = var.broker_url
  }
}

resource "hpegl_vmaas_instance" "web" {
  name     = "web"
  cloud_id = 1
  group_id = 2
}

resource "hpegl_vmaas_router_nat_rule" "snat" {
  router_id = 7
  name      = "snat"
}

resource "hpegl_metal_host" "db" {
  hostname = "db"
}
