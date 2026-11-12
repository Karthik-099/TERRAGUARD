# expect: TG-SECRET-013, TG-SECRET-014
provider "nutanix" {
  username = "admin"
  password = "Nutanix/4u"
  endpoint = "10.0.0.10"
  insecure = true
}

# TG-SEC-001 covers resource arguments; locals and variable defaults are TG-SECRET-014.
locals {
  api_key = "Hn4cW8qZ2rTj6LmX9vBd"
}
