# forbid: TG-CF-004, TG-CF-005, TG-CF-006, TG-CF-007, TG-CF-008, TG-CF-010, TG-CF-011
resource "cloudflare_zero_trust_access_application" "app" {
  name             = "internal"
  domain           = "internal.example.com"
  session_duration = "12h"
}
resource "cloudflare_access_policy" "team" {
  name     = "team"
  decision = "allow"
  include {
    email_domain = ["example.com"]
  }
}
resource "cloudflare_api_token" "ci" {
  name       = "ci"
  expires_on = "2027-01-01T00:00:00Z"
}
resource "cloudflare_ruleset" "skip" {
  zone_id = "abc"
  name    = "skip health"
  kind    = "zone"
  phase   = "http_request_firewall_custom"
  rules {
    action     = "skip"
    expression = "http.request.uri.path eq \"/healthz\""
  }
}
