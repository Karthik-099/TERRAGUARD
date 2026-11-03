# expect: TG-CF-004, TG-CF-005, TG-CF-006, TG-CF-007, TG-CF-008, TG-CF-010, TG-CF-011
resource "cloudflare_zero_trust_access_application" "app" {
  name             = "internal"
  domain           = "internal.example.com"
  session_duration = "720h"
}
resource "cloudflare_access_policy" "all" {
  name     = "everyone"
  decision = "allow"
  include {
    everyone = true
  }
}
resource "cloudflare_r2_managed_domain" "pub" {
  bucket_name = "data"
  enabled     = true
}
resource "cloudflare_api_token" "ci" {
  name = "ci"
}
resource "cloudflare_zone_settings_override" "z" {
  zone_id = "abc"
  settings {
    security_level = "essentially_off"
  }
}
resource "cloudflare_ruleset" "skip" {
  zone_id = "abc"
  name    = "skip all"
  kind    = "zone"
  phase   = "http_request_firewall_custom"
  rules {
    action     = "skip"
    expression = "true"
  }
}
resource "cloudflare_tunnel_config" "t" {
  account_id = "a"
  tunnel_id  = "t"
  config {
    ingress_rule {
      service = "https://origin:443"
      origin_request {
        no_tls_verify = true
      }
    }
  }
}
