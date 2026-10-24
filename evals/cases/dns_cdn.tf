# expect: TG-DNS-001, TG-DNS-002, TG-DNS-003, TG-CDN-001
resource "aws_route53_zone" "public" {
  name = "example.com"
}
resource "aws_route53_record" "blog" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "blog"
  type    = "CNAME"
  ttl     = 300
  records = ["acme-blog.herokuapp.com"]
}
resource "google_dns_managed_zone" "z" {
  name     = "z"
  dns_name = "example.org."
}
resource "azurerm_cdn_endpoint" "e" {
  name                = "e"
  profile_name        = "p"
  resource_group_name = "rg"
  location            = "global"
}
