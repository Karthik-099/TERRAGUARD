package engine

import (
	"fmt"
	"strings"
	"testing"
)

// Every generated rule must fire on a resource with a bad value and stay quiet
// on one with the value it asks for.
func TestParityChecksFireAndClear(t *testing.T) {
	for _, c := range append(append(append([]check{}, parityChecks...), cfnParityChecks...), armParityChecks...) {
		var bad, good any
		switch c.Kind {
		case "want":
			bad, good = badFor(c.Want), c.Want[0]
		case "set":
			bad, good = nil, "configured"
		case "eq", "missing_or_eq":
			bad, good = c.Bad[0], "terraguard-safe-value"
		case "present":
			bad, good = "anything", nil
		}
		for _, tc := range []struct {
			v    any
			fire bool
		}{{bad, true}, {good, false}} {
			src := fmt.Sprintf("resource %q \"x\" {\n%s}\n", c.Types[0], nested(strings.Split(c.Path, "."), tc.v))
			got := false
			for _, f := range Scan(Input{Files: map[string]string{"main.tf": src}, Only: []string{c.ID}}).Findings {
				got = got || f.RuleID == c.ID
			}
			if got != tc.fire {
				t.Errorf("%s with %s = %v: fired=%v\n%s", c.ID, c.Path, tc.v, got, src)
			}
		}
	}
}

func badFor(want []any) any {
	switch want[0].(type) {
	case bool:
		return !want[0].(bool)
	case float64, int:
		return -12345
	}
	return "terraguard-bad-value"
}

// nested writes a.0.b = v as a { b = v }; a nil value writes nothing.
func nested(path []string, v any) string {
	if v == nil {
		return ""
	}
	if len(path) == 1 {
		return fmt.Sprintf("  %s = %s\n", path[0], literal(v))
	}
	if path[1] == "0" {
		path = append([]string{path[0]}, path[2:]...)
		if len(path) == 1 {
			return nested(path, v)
		}
	}
	return fmt.Sprintf("  %s {\n%s  }\n", path[0], nested(path[1:], v))
}
