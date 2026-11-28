# forbid: TG-AWS-S3-001, TG-CFN-S3-102, TG-VAL-001
# A private bucket in the template, and a file() source, which is scanned on its own.
resource "hpe_morpheus_app_blueprint_terraform" "site" {
  name              = "site"
  source_type       = "hcl"
  blueprint_content = <<-EOT
    resource "aws_s3_bucket_acl" "site" {
      bucket = "site-assets"
      acl    = "private"
    }
  EOT
}

resource "hpe_morpheus_app_blueprint_cloud_formation" "site" {
  name              = "site-cfn"
  source_type       = "yaml"
  blueprint_content = file("${path.module}/site.yaml")
}
