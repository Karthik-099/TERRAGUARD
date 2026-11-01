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
	Extends           []string            `yaml:"extends,omitempty" json:"extends,omitempty"` // base policy packs, resolved by ResolveExtends
	FailOn            Severity            `yaml:"fail_on,omitempty" json:"fail_on"`
	Disable           []string            `yaml:"disable,omitempty" json:"disable"`                       // rule IDs or globs (TG-CF-*)
	SeverityOverrides map[string]Severity `yaml:"severity_overrides,omitempty" json:"severity_overrides"` // keys may be globs
	Waivers           []Waiver            `yaml:"waivers,omitempty" json:"waivers"`
	CustomRules       []CustomRule        `yaml:"custom_rules,omitempty" json:"custom_rules"`
	// MaxFindings is a risk budget: the gate fails when a severity exceeds its count.
	MaxFindings map[Severity]int `yaml:"max_findings,omitempty" json:"max_findings,omitempty"`
}

// Waiver is an auditable exception: who accepted which risk, why, until when.
type Waiver struct {
	Rule       string `yaml:"rule" json:"rule"`                   // rule ID or glob
	Resource   string `yaml:"resource,omitempty" json:"resource"` // glob, empty = any
	Reason     string `yaml:"reason,omitempty" json:"reason"`
	Expires    string `yaml:"expires,omitempty" json:"expires"` // YYYY-MM-DD
	ApprovedBy string `yaml:"approved_by,omitempty" json:"approved_by"`
}

// Condition tests one attribute. Every operator that is set must hold.
type Condition struct {
	Attribute  string   `yaml:"attribute,omitempty" json:"attribute,omitempty"`
	Exists     *bool    `yaml:"exists,omitempty" json:"exists,omitempty"`
	Equals     any      `yaml:"equals,omitempty" json:"equals,omitempty"`
	NotEquals  any      `yaml:"not_equals,omitempty" json:"not_equals,omitempty"`
	In         []any    `yaml:"in,omitempty" json:"in,omitempty"`
	NotIn      []any    `yaml:"not_in,omitempty" json:"not_in,omitempty"`
	Matches    string   `yaml:"matches,omitempty" json:"matches,omitempty"`
	NotMatches string   `yaml:"not_matches,omitempty" json:"not_matches,omitempty"`
	Contains   any      `yaml:"contains,omitempty" json:"contains,omitempty"` // list element, map key or substring
	Min        *float64 `yaml:"min,omitempty" json:"min,omitempty"`
	Max        *float64 `yaml:"max,omitempty" json:"max,omitempty"`
	re, notRe  *regexp.Regexp
}

// CustomRule is an organization standard: for resources of ResourceTypes that
// satisfy every Where condition, the inline condition and every Assert must hold.
type CustomRule struct {
	ID            string      `yaml:"id" json:"id"`
	Title         string      `yaml:"title,omitempty" json:"title"`
	Severity      Severity    `yaml:"severity,omitempty" json:"severity"`
	Remediation   string      `yaml:"remediation,omitempty" json:"remediation"`
	Owner         string      `yaml:"owner,omitempty" json:"owner,omitempty"`
	DocsURL       string      `yaml:"docs_url,omitempty" json:"docs_url,omitempty"`
	ResourceTypes []string    `yaml:"resource_types,omitempty" json:"resource_types"` // globs
	Where         []Condition `yaml:"where,omitempty" json:"where,omitempty"`
	Assert        []Condition `yaml:"assert,omitempty" json:"assert,omitempty"`
	Condition     `yaml:",inline"`
}

func (c *Condition) compile(where string) error {
	if c.Attribute == "" {
		return fmt.Errorf("%s: attribute is required", where)
	}
	var err error
	if c.Matches != "" {
		if c.re, err = regexp.Compile(c.Matches); err != nil {
			return fmt.Errorf("%s.matches: %w", where, err)
		}
	}
	if c.NotMatches != "" {
		if c.notRe, err = regexp.Compile(c.NotMatches); err != nil {
			return fmt.Errorf("%s.not_matches: %w", where, err)
		}
	}
	return nil
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
	if c.FailOn.Rank() == 0 && c.FailOn != "NONE" {
		return nil, fmt.Errorf(".terraguard.yml: fail_on must be CRITICAL, HIGH, MEDIUM, LOW, INFO or NONE (got %q)", c.FailOn)
	}
	budgets := map[Severity]int{}
	for k, v := range c.MaxFindings {
		sev := ParseSeverity(string(k))
		if sev.Rank() == 0 || v < 0 {
			return nil, fmt.Errorf(".terraguard.yml: max_findings: invalid entry %s: %d", k, v)
		}
		budgets[sev] = v
	}
	c.MaxFindings = budgets
	ids := map[string]bool{}
	for i := range c.CustomRules {
		cr := &c.CustomRules[i]
		if cr.ID == "" {
			return nil, fmt.Errorf("custom_rules[%d]: id is required", i)
		}
		if ids[cr.ID] {
			return nil, fmt.Errorf("custom_rules: duplicate id %s", cr.ID)
		}
		ids[cr.ID] = true
		if cr.Severity == "" {
			cr.Severity = Medium
		}
		cr.Severity = ParseSeverity(string(cr.Severity))
		if cr.Attribute == "" && len(cr.Assert) == 0 {
			return nil, fmt.Errorf("custom_rules[%s]: needs an attribute condition or an assert list", cr.ID)
		}
		if cr.Attribute != "" {
			if err := cr.Condition.compile("custom_rules[" + cr.ID + "]"); err != nil {
				return nil, err
			}
		}
		for j := range cr.Assert {
			if err := cr.Assert[j].compile(fmt.Sprintf("custom_rules[%s].assert[%d]", cr.ID, j)); err != nil {
				return nil, err
			}
		}
		for j := range cr.Where {
			if err := cr.Where[j].compile(fmt.Sprintf("custom_rules[%s].where[%d]", cr.ID, j)); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

// ResolveExtends merges policy packs listed in `extends` (depth-first, base
// first) into one config document. load fetches a reference relative to the
// document that names it; the engine itself never does I/O.
func ResolveExtends(src string, load func(ref string) (string, error)) (string, error) {
	merged, err := resolve(src, load, map[string]bool{}, 0)
	if err != nil {
		return "", err
	}
	b, err := yaml.Marshal(merged)
	return string(b), err
}

func resolve(src string, load func(string) (string, error), seen map[string]bool, depth int) (*Config, error) {
	if depth > 8 {
		return nil, fmt.Errorf("extends: nested more than 8 levels")
	}
	c := &Config{}
	if err := yaml.Unmarshal([]byte(src), c); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	out := &Config{}
	for _, ref := range c.Extends {
		if seen[ref] {
			return nil, fmt.Errorf("extends: cycle through %s", ref)
		}
		seen[ref] = true
		text, err := load(ref)
		if err != nil {
			return nil, fmt.Errorf("extends %s: %w", ref, err)
		}
		base, err := resolve(text, load, seen, depth+1)
		if err != nil {
			return nil, err
		}
		mergeInto(out, base)
	}
	c.Extends = nil
	mergeInto(out, c)
	return out, nil
}

// mergeInto layers child over base: scalars and same-ID rules are replaced,
// lists are appended.
func mergeInto(base, child *Config) {
	if child.FailOn != "" {
		base.FailOn = child.FailOn
	}
	base.Disable = append(base.Disable, child.Disable...)
	for k, v := range child.SeverityOverrides {
		if base.SeverityOverrides == nil {
			base.SeverityOverrides = map[string]Severity{}
		}
		base.SeverityOverrides[k] = v
	}
	base.Waivers = append(base.Waivers, child.Waivers...)
	for k, v := range child.MaxFindings {
		if base.MaxFindings == nil {
			base.MaxFindings = map[Severity]int{}
		}
		base.MaxFindings[k] = v
	}
	for _, cr := range child.CustomRules {
		replaced := false
		for i := range base.CustomRules {
			if base.CustomRules[i].ID == cr.ID {
				base.CustomRules[i], replaced = cr, true
			}
		}
		if !replaced {
			base.CustomRules = append(base.CustomRules, cr)
		}
	}
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

// eval returns ok=false with a reason when the condition does not hold.
// known=false means the value is computed at plan time and cannot be judged.
func (c *Condition) eval(r *Resource) (ok, known bool, why string) {
	v := r.get(c.Attribute)
	if isUnknown(v) {
		return true, false, ""
	}
	a := c.Attribute
	if c.Exists != nil && (v != nil) != *c.Exists {
		if *c.Exists {
			return false, true, a + " must be set"
		}
		return false, true, a + " must not be set"
	}
	if c.Equals != nil && !same(v, c.Equals) {
		return false, true, fmt.Sprintf("%s must equal %v (got %v)", a, c.Equals, v)
	}
	if c.NotEquals != nil && v != nil && same(v, c.NotEquals) {
		return false, true, fmt.Sprintf("%s must not be %v", a, c.NotEquals)
	}
	if c.In != nil {
		found := false
		for _, x := range c.In {
			found = found || same(v, x)
		}
		if !found {
			return false, true, fmt.Sprintf("%s must be one of %v (got %v)", a, c.In, v)
		}
	}
	for _, x := range c.NotIn {
		if v != nil && same(v, x) {
			return false, true, fmt.Sprintf("%s = %v is not allowed", a, v)
		}
	}
	s, _ := asString(v)
	if c.re != nil && !c.re.MatchString(s) {
		return false, true, fmt.Sprintf("%s must match %s (got %q)", a, c.Matches, s)
	}
	if c.notRe != nil && v != nil && c.notRe.MatchString(s) {
		return false, true, fmt.Sprintf("%s must not match %s (got %q)", a, c.NotMatches, s)
	}
	if c.Contains != nil && !containsValue(v, c.Contains) {
		return false, true, fmt.Sprintf("%s must contain %v", a, c.Contains)
	}
	if c.Min != nil || c.Max != nil {
		n, isNum := asFloat(v)
		if !isNum {
			return false, true, fmt.Sprintf("%s must be a number", a)
		}
		if c.Min != nil && n < *c.Min {
			return false, true, fmt.Sprintf("%s must be at least %v (got %v)", a, *c.Min, n)
		}
		if c.Max != nil && n > *c.Max {
			return false, true, fmt.Sprintf("%s must be at most %v (got %v)", a, *c.Max, n)
		}
	}
	return true, true, ""
}

func containsValue(v, want any) bool {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if same(e, want) {
				return true
			}
		}
	case map[string]any:
		_, ok := t[fmt.Sprint(want)]
		return ok
	case string:
		return strings.Contains(t, fmt.Sprint(want))
	}
	return false
}

func (cr *CustomRule) check(r *Resource) (string, bool) {
	if len(cr.ResourceTypes) > 0 && !globAny(cr.ResourceTypes, r.Type) {
		return "", false
	}
	for i := range cr.Where {
		if ok, known, _ := cr.Where[i].eval(r); !ok || !known {
			return "", false // filter not met, or unknown at static time
		}
	}
	conds := cr.Assert
	if cr.Attribute != "" {
		conds = append([]Condition{cr.Condition}, conds...)
	}
	for i := range conds {
		if ok, _, why := conds[i].eval(r); !ok {
			return why, true
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
	override := func(id string) (Severity, bool) {
		if s, ok := cfg.SeverityOverrides[id]; ok {
			return s, true
		}
		for k, s := range cfg.SeverityOverrides {
			if ok, _ := path.Match(k, id); ok {
				return s, true
			}
		}
		return "", false
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
		if globAny(cfg.Disable, f.RuleID) {
			continue
		}
		if s, ok := override(f.RuleID); ok {
			f.Severity = ParseSeverity(string(s))
		}
		if ignored(f) {
			f.Waived, f.WaiverReason = true, "inline terraguard:ignore comment"
		}
		for i, w := range cfg.Waivers {
			if ruleMatch, _ := path.Match(w.Rule, f.RuleID); f.Waived || !ruleMatch {
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
