# expect: TG-AWS-S3-001, TG-CFN-S3-102
# Templates inline in HPE Morpheus app blueprints are scanned as their own format.
resource "hpe_morpheus_app_blueprint_terraform" "site" {
  name              = "site"
  source_type       = "hcl"
  blueprint_content = <<-EOT
    resource "aws_s3_bucket_acl" "site" {
      bucket = "site-assets"
      acl    = "public-read"
    }
  EOT
}

resource "hpe_morpheus_app_blueprint_cloud_formation" "site" {
  name              = "site-cfn"
  source_type       = "yaml"
  blueprint_content = <<EOF
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Site:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
EOF
}
