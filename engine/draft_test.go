package engine

import (
	"strings"
	"testing"
)

func TestDraftRuleValidatesAndDryRuns(t *testing.T) {
	files := map[string]string{"main.tf": `
resource "aws_db_instance" "prod" {
  backup_retention_period = 3
  tags = { env = "prod" }
}
resource "aws_db_instance" "dev" {
  backup_retention_period = 1
  tags = { env = "dev" }
}`}
	proposal := "```yaml\nid: org-db-001\ntitle: Prod databases keep 14 days of backups\nseverity: HIGH\nresource_types: [aws_db_instance]\nwhere:\n  - {attribute: tags.env, equals: prod}\nassert:\n  - {attribute: backup_retention_period, min: 14}\n```"
	d := DraftRule(proposal, Input{Files: files})
	if d.Error != "" {
		t.Fatal(d.Error)
	}
	if len(d.Hits) != 1 || d.Hits[0].Resource != "aws_db_instance.prod" {
		t.Fatalf("want one hit on the prod database, got %+v", d.Hits)
	}
	if !strings.HasPrefix(d.YAML, "  - id: ORG-DB-001") {
		t.Fatalf("canonical YAML should be one custom_rules item:\n%s", d.YAML)
	}
	// The canonical YAML must round-trip as a policy.
	if _, err := ParseConfig("custom_rules:\n" + d.YAML); err != nil {
		t.Fatal(err)
	}
}

func TestDraftRuleCannotWeakenPolicy(t *testing.T) {
	for name, proposal := range map[string]string{
		"extra top-level key": "id: ORG-X-001\nresource_types: [aws_*]\nattribute: tags.owner\nexists: true\ndisable: [\"*\"]",
		"waiver smuggled":     "custom_rules:\n  - id: ORG-X-001\n    resource_types: [aws_*]\n    attribute: tags.owner\n    exists: true\nwaivers:\n  - rule: \"*\"",
		"two rules":           "- {id: ORG-A-001, resource_types: [aws_*], attribute: a, exists: true}\n- {id: ORG-B-001, resource_types: [aws_*], attribute: b, exists: true}",
		"built-in id":         "id: TG-AWS-S3-001\nresource_types: [aws_s3_bucket]\nattribute: acl\nexists: false",
		"matches everything":  "id: ORG-X-001\nattribute: tags.owner\nexists: true",
		"no condition":        "id: ORG-X-001\nresource_types: [aws_*]",
		"bad regex":           "id: ORG-X-001\nresource_types: [aws_*]\nattribute: name\nmatches: \"(\"",
	} {
		if d := DraftRule(proposal, Input{}); d.Error == "" {
			t.Errorf("%s: accepted:\n%s", name, d.YAML)
		}
	}
}
