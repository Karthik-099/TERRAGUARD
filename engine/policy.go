package engine

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is .terraguard.yml: the team's engineering standards as code.
type Config struct {
	FailOn            Severity            `yaml:"fail_on" json:"fail_on"`
	Disable           []string            `yaml:"disable" json:"disable"`
	SeverityOverrides map[string]Severity `yaml:"severity_overrides" json:"severity_overrides"`
	Waivers           []Waiver            `yaml:"waivers" json:"waivers"`
	CustomRules       []CustomRule        `yaml:"custom_rules" json:"custom_rules"`
}

// Waiver is an auditable exception: who accepted which risk, why, until when.
type Waiver struct {
	Rule       string `yaml:"rule" json:"rule"`
	Resource   string `yaml:"resource" json:"resource"` // glob, empty = any
	Reason     string `yaml:"reason" json:"reason"`
	Expires    string `yaml:"expires" json:"expires"` // YYYY-MM-DD
	ApprovedBy string `yaml:"approved_by" json:"approved_by"`
}

// CustomRule asserts one attribute condition; a resource that fails it is a finding.
type CustomRule struct {
	ID            string   `yaml:"id" json:"id"`
	Title         string   `yaml:"title" json:"title"`
	Severity      Severity `yaml:"severity" json:"severity"`
	Remediation   string   `yaml:"remediation" json:"remediation"`
	ResourceTypes []string `yaml:"resource_types" json:"resource_types"` // globs
	Attribute     string   `yaml:"attribute" json:"attribute"`
	Exists        *bool    `yaml:"exists" json:"exists"`
	Equals        any      `yaml:"equals" json:"equals"`
	NotEquals     any      `yaml:"not_equals" json:"not_equals"`
	In            []any    `yaml:"in" json:"in"`
	NotIn         []any    `yaml:"not_in" json:"not_in"`
	Matches       string   `yaml:"matches" json:"matches"`
	re            *regexp.Regexp
}

func ParseConfig(src string) (*Config, error) {
	c := &Config{}
	if strings.TrimSpace(src) != "" {
		if err := yaml.Unmarshal([]byte(src), c); err != nil {
			return nil, fmt.Errorf(".terraguard.yml: %w", err)
		}
	}
	if c.FailOn == "" {
		c.FailOn = High
	}
	c.FailOn = ParseSeverity(string(c.FailOn))
	for i := range c.CustomRules {
		cr := &c.CustomRules[i]
		if cr.ID == "" || cr.Attribute == "" {
			return nil, fmt.Errorf("custom_rules[%d]: id and attribute are required", i)
		}
		if cr.Severity == "" {
			cr.Severity = Medium
		}
		cr.Severity = ParseSeverity(string(cr.Severity))
		if cr.Matches != "" {
			re, err := regexp.Compile(cr.Matches)
			if err != nil {
				return nil, fmt.Errorf("custom_rules[%s].matches: %w", cr.ID, err)
			}
			cr.re = re
		}
	}
	return c, nil
}

func globAny(globs []string, s string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, s); ok {
			return true
		}
	}
	return false
}

func same(a, b any) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

func (cr *CustomRule) check(r *Resource) (string, bool) {
	if len(cr.ResourceTypes) > 0 && !globAny(cr.ResourceTypes, r.Type) {
		return "", false
	}
	v := r.get(cr.Attribute)
	if isUnknown(v) {
		return "", false // computed at plan time; can't judge statically
	}
	switch {
	case cr.Exists != nil:
		if (v != nil) != *cr.Exists {
			if *cr.Exists {
				return cr.Attribute + " must be set", true
			}
			return cr.Attribute + " must not be set", true
		}
	case cr.Equals != nil:
		if !same(v, cr.Equals) {
			return fmt.Sprintf("%s must equal %v (got %v)", cr.Attribute, cr.Equals, v), true
		}
	case cr.NotEquals != nil:
		if v != nil && same(v, cr.NotEquals) {
			return fmt.Sprintf("%s must not be %v", cr.Attribute, cr.NotEquals), true
		}
	case cr.In != nil:
		for _, x := range cr.In {
			if same(v, x) {
				return "", false
			}
		}
		return fmt.Sprintf("%s must be one of %v (got %v)", cr.Attribute, cr.In, v), true
	case cr.NotIn != nil:
		for _, x := range cr.NotIn {
			if v != nil && same(v, x) {
				return fmt.Sprintf("%s = %v is not allowed", cr.Attribute, v), true
			}
		}
	case cr.re != nil:
		s, _ := asString(v)
		if !cr.re.MatchString(s) {
			return fmt.Sprintf("%s must match %s (got %q)", cr.Attribute, cr.Matches, s), true
		}
	}
	return "", false
}

var ignoreRE = regexp.MustCompile(`(?:#|//)\s*terraguard:ignore[:\s]+([A-Za-z0-9_,\- *]+)`)

// inlineIgnores maps file -> line -> rule IDs from `# terraguard:ignore TG-X` comments.
func inlineIgnores(files map[string][]byte) map[string]map[int][]string {
	out := map[string]map[int][]string{}
	for name, src := range files {
		for i, line := range strings.Split(string(src), "\n") {
			m := ignoreRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if out[name] == nil {
				out[name] = map[int][]string{}
			}
			for _, id := range strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' }) {
				out[name][i+1] = append(out[name][i+1], strings.TrimSpace(id))
			}
		}
	}
	return out
}

func applyPolicy(fs []Finding, cfg *Config, ign map[string]map[int][]string, blockLine map[string]int, now time.Time) []Finding {
	disabled := map[string]bool{}
	for _, id := range cfg.Disable {
		disabled[id] = true
	}
	ignored := func(f Finding) bool {
		lines := ign[f.File]
		for _, l := range []int{f.Line, f.Line - 1, blockLine[f.Resource] - 1} {
			for _, id := range lines[l] {
				if id == f.RuleID || id == "*" {
					return true
				}
			}
		}
		return false
	}
	var out []Finding
	expiredSeen := map[int]bool{}
	for _, f := range fs {
		if disabled[f.RuleID] {
			continue
		}
		if s, ok := cfg.SeverityOverrides[f.RuleID]; ok {
			f.Severity = ParseSeverity(string(s))
		}
		if ignored(f) {
			f.Waived, f.WaiverReason = true, "inline terraguard:ignore comment"
		}
		for i, w := range cfg.Waivers {
			if f.Waived || (w.Rule != f.RuleID && w.Rule != "*") {
				continue
			}
			if w.Resource != "" {
				if ok, _ := path.Match(w.Resource, f.Resource); !ok {
					continue
				}
			}
			if w.Expires != "" {
				exp, err := time.Parse("2006-01-02", w.Expires)
				if err != nil || now.After(exp.Add(24*time.Hour)) {
					if !expiredSeen[i] {
						expiredSeen[i] = true
						out = append(out, newFinding("TG-POL-001", "", fmt.Sprintf("Waiver for %s on %s expired on %s (approved by %s). The underlying finding is active again.", w.Rule, orDash(w.Resource), w.Expires, orDash(w.ApprovedBy)), f.Resource, ".terraguard.yml", 0))
					}
					continue
				}
			}
			f.Waived = true
			f.WaiverReason = w.Reason
			if w.ApprovedBy != "" {
				f.WaiverReason += " (approved by " + w.ApprovedBy + ")"
			}
		}
		out = append(out, f)
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
