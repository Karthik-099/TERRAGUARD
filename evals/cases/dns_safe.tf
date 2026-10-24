# forbid: TG-DNS-001, TG-DNS-003
resource "aws_route53_zone" "public" {
  name = "example.com"
}
resource "aws_route53_hosted_zone_dnssec" "public" {
  hosted_zone_id = aws_route53_zone.public.id
}
resource "aws_cloudfront_distribution" "site" {
  enabled = true
}
resource "aws_route53_record" "www" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "www"
  type    = "CNAME"
  ttl     = 300
  records = [aws_cloudfront_distribution.site.domain_name]
}
