# expect: TG-CF-001, TG-CF-002
resource "cloudflare_zone_setting" "ssl" {
  zone_id    = "abc"
  setting_id = "ssl"
  value      = "flexible"
}
resource "cloudflare_dns_record" "origin" {
  zone_id = "abc"
  name    = "app"
  type    = "A"
  content = "203.0.113.10"
  proxied = false
}
