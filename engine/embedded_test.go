package engine

import (
	"strings"
	"testing"
)

func TestEmbeddedBlueprintTemplates(t *testing.T) {
	tf := `resource "hpe_morpheus_app_blueprint_terraform" "bp" {
  name              = "bp"
  source_type       = "hcl"
  blueprint_content = <<-EOT
    resource "aws_s3_bucket_acl" "public" {
      bucket = "data"
      acl    = "public-read"
    }
  EOT
}
`
	cfn := `resource "hpe_morpheus_app_blueprint_cloud_formation" "cf" {
  name              = "cf"
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
`
	broken := `resource "hpe_morpheus_app_blueprint_terraform" "bad" {
  name              = "bad"
  source_type       = "hcl"
  blueprint_content = "resource \"aws_s3_bucket_acl\" {{{"
}

resource "hpe_morpheus_app_blueprint_cloud_formation" "bad" {
  name              = "bad"
  source_type       = "json"
  blueprint_content = "{\"AWSTemplateFormatVersion\": [,"
}

resource "hpe_morpheus_app_blueprint_terraform" "file" {
  name              = "file"
  source_type       = "hcl"
  blueprint_content = file("template.tf")
}
`
	find := func(files map[string]string, id string) *Finding {
		for _, f := range Scan(Input{Files: files}).Findings {
			if f.RuleID == id {
				return &f
			}
		}
		return nil
	}
	if f := find(map[string]string{"bp.tf": tf}, "TG-AWS-S3-001"); f == nil {
		t.Fatal("the S3 finding inside the Terraform blueprint is missing")
	} else if f.File != "bp.tf" || f.Line != 7 || f.Fix != nil || !strings.HasPrefix(f.Message, "In hpe_morpheus_app_blueprint_terraform.bp.blueprint_content: ") {
		t.Errorf("Terraform blueprint finding: %+v", *f)
	}
	if f := find(map[string]string{"cf.tf": cfn}, "TG-CFN-S3-102"); f == nil {
		t.Fatal("the S3 finding inside the CloudFormation blueprint is missing")
	} else if f.File != "cf.tf" || f.Line != 9 || !strings.Contains(f.Message, "hpe_morpheus_app_blueprint_cloud_formation.cf") {
		t.Errorf("CloudFormation blueprint finding: %+v", *f)
	}
	for _, f := range Scan(Input{Files: map[string]string{"broken.tf": broken}}).Findings {
		if strings.HasPrefix(f.Message, "In ") {
			t.Errorf("a malformed or file() template must give no finding: %s %s", f.RuleID, f.Message)
		}
	}
}

// Spec templates use spec_content with source_type "local"; the format comes from
// the resource type, and JSON content is read as JSON.
func TestEmbeddedSpecTemplates(t *testing.T) {
	src := `resource "hpe_morpheus_spec_template_cloud_formation" "cf" {
  name         = "cf"
  source_type  = "local"
  spec_content = <<EOF
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Site:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
EOF
}

resource "hpe_morpheus_spec_template_terraform" "tfjson" {
  name         = "tfjson"
  source_type  = "local"
  spec_content = <<EOF
{"resource": {"aws_s3_bucket_acl": {"public": {"bucket": "data", "acl": "public-read"}}}}
EOF
}

resource "hpe_morpheus_spec_template_terraform" "remote" {
  name        = "remote"
  source_type = "url"
}
`
	got := map[string]bool{}
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}}).Findings {
		if strings.HasPrefix(f.Message, "In ") {
			got[f.Resource] = true
			if f.File != "main.tf" || f.Fix != nil {
				t.Errorf("%s: file %q fix %v; want main.tf and no fix", f.RuleID, f.File, f.Fix)
			}
		}
	}
	for _, r := range []string{"hpe_morpheus_spec_template_cloud_formation.cf", "hpe_morpheus_spec_template_terraform.tfjson"} {
		if !got[r] {
			t.Errorf("no finding inside %s (got %v)", r, got)
		}
	}
	if got["hpe_morpheus_spec_template_terraform.remote"] {
		t.Error("a url spec template has no inline content to scan")
	}
}
