package engine

import (
	"fmt"
	"strings"
	"testing"
)

// hclFor writes a resource that sets path (nested blocks for each parent) to v,
// or an empty resource when v is nil.
func hclFor(typ, path string, v any) string {
	if v == nil {
		return fmt.Sprintf("resource %q \"x\" {}\n", typ)
	}
	segs := strings.Split(path, ".")
	body := fmt.Sprintf("%s = %s", segs[len(segs)-1], literal(v))
	for i := len(segs) - 2; i >= 0; i-- {
		body = fmt.Sprintf("%s {\n%s\n}", segs[i], body)
	}
	return fmt.Sprintf("resource %q \"x\" {\n%s\n}\n", typ, body)
}

func fires(id, src string) bool {
	for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}}).Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestTableChecksFireAndStayQuiet(t *testing.T) {
	for _, c := range tableChecks {
		var bad any
		switch c.Kind {
		case "eq", "missing_or_eq":
			bad = c.Bad[0]
		case "gt":
			bad = c.Num + 1
		case "lt":
			bad = c.Num - 1
		}
		good := c.Good
		if good == nil {
			good = "configured"
		}
		for _, typ := range c.Types[:1] {
			if src := hclFor(typ, c.Path, bad); !fires(c.ID, src) {
				t.Errorf("%s should fire on:\n%s", c.ID, src)
			}
			if c.Kind == "missing_or_eq" || c.Kind == "lt_or_missing" {
				if src := hclFor(typ, c.Path, nil); !fires(c.ID, src) {
					t.Errorf("%s should fire when %s is absent", c.ID, c.Path)
				}
			}
			if src := hclFor(typ, c.Path, good); fires(c.ID, src) {
				t.Errorf("%s should stay quiet on:\n%s", c.ID, src)
			}
		}
		if c.Fixable && c.Good == nil {
			t.Errorf("%s is fixable but has no safe value", c.ID)
		}
	}
}

func TestTableFixesApply(t *testing.T) {
	for _, c := range tableChecks {
		if !c.Fixable || (c.Kind != "eq" && c.Kind != "gt") {
			continue
		}
		bad := any(c.Num + 1)
		if c.Kind == "eq" {
			bad = c.Bad[0]
		}
		in := Input{Files: map[string]string{"main.tf": hclFor(c.Types[0], c.Path, bad)}}
		fixed, errs := FixAll(in)
		if len(errs) > 0 || fixes(c.ID, fixed["main.tf"]) {
			t.Errorf("%s: fix did not clear the finding (errors %v):\n%s", c.ID, errs, fixed["main.tf"])
		}
	}
}

func fixes(id, src string) bool { return src == "" || fires(id, src) }
