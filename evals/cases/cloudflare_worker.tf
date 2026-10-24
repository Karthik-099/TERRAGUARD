# expect: TG-CF-003, TG-CF-001
resource "cloudflare_workers_script" "api" {
  account_id = "a"
  name       = "api"
  content    = "export default {}"
  plain_text_binding {
    name = "STRIPE_SECRET"
    text = "sk_live_123"
  }
}
resource "cloudflare_zone_setting" "sec" {
  zone_id    = "z"
  setting_id = "security_level"
  value      = "essentially_off"
}
