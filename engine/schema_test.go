package engine

import "testing"

const testSchema = `{"format_version":"1.0","provider_schemas":{"registry.terraform.io/hashicorp/aws":{
 "resource_schemas":{"aws_thing":{"block":{
  "attributes":{"name":{"required":true},"size":{"optional":true},"arn":{"computed":true},"old":{"optional":true,"deprecated":true},"tags":{"optional":true}},
  "block_types":{"rule":{"nesting_mode":"list","min_items":1,"block":{"attributes":{"port":{"required":true}}}},
                 "one":{"nesting_mode":"list","max_items":1,"block":{"attributes":{"x":{"optional":true}}}}}}}},
 "data_source_schemas":{}}}}`

func TestSchemaChecks(t *testing.T) {
	r := Scan(Input{Schema: testSchema, Files: map[string]string{"main.tf": `
resource "aws_thing" "bad" {
  nmae = "x"
  arn  = "arn:x"
  old  = 1
  tags {
    a = "b"
  }
  one {
    x = 1
  }
  one {
    x = 2
  }
}

resource "aws_thing" "good" {
  count = 2
  name  = "x"
  tags  = { a = "b" }
  dynamic "rule" {
    for_each = [80]
    content {
      port = rule.value
    }
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "other_thing" "skipped" {
  anything = true
}
`}})
	got := map[string][]string{}
	for _, f := range r.Findings {
		if len(f.RuleID) > 9 && f.RuleID[:9] == "TG-SCHEMA" {
			got[f.Resource] = append(got[f.Resource], f.RuleID+" "+f.Message)
		}
	}
	if len(got["aws_thing.good"]) > 0 || len(got["other_thing.skipped"]) > 0 {
		t.Errorf("false positives: %v", got)
	}
	want := []string{
		`TG-SCHEMA-001 aws_thing does not support argument "nmae". Did you mean "name"?`,
		`TG-SCHEMA-001 aws_thing: "arn" is read-only; the provider sets it.`,
		`TG-SCHEMA-003 aws_thing: "old" is deprecated.`,
		`TG-SCHEMA-001 aws_thing: "tags" is an argument, not a block; write tags = { ... }.`,
		`TG-SCHEMA-001 aws_thing allows at most 1 "one" block(s).`,
		`TG-SCHEMA-002 aws_thing is missing required argument "name".`,
		`TG-SCHEMA-002 aws_thing needs at least 1 "rule" block(s).`,
	}
	have := map[string]bool{}
	for _, m := range got["aws_thing.bad"] {
		have[m] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("missing %q\ngot: %v", w, got["aws_thing.bad"])
		}
	}
	if bad := Scan(Input{Schema: "{}", Files: map[string]string{"main.tf": ""}}); len(bad.Errors) == 0 {
		t.Error("an empty schema should be reported as an error")
	}
}
