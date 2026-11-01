package engine

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleDraftPrompt asks a model for one custom rule; DraftRule checks what comes back.
const RuleDraftPrompt = `You convert an organization's infrastructure standard, written in plain English, into exactly ONE TerraGuard custom rule for Terraform.
Answer with YAML only: a single mapping, no list dash, no prose, no code fences.
Allowed keys: id, title, severity, remediation, resource_types, where, assert, attribute, exists, equals, not_equals, in, not_in, matches, not_matches, contains, min, max.
- id: uppercase letters, digits and dashes, starting with ORG- (for example ORG-DB-001).
- severity: CRITICAL, HIGH, MEDIUM, LOW or INFO.
- resource_types: Terraform resource type globs, for example ["aws_db_instance"] or ["aws_*"].
- where: optional list of conditions selecting resources; assert: list of conditions that must hold.
- A condition is {attribute: <dot path through attributes and nested blocks, e.g. tags.env or settings.backup_configuration.enabled>, <operator>: <value>}.
- Operators: exists (true/false), equals, not_equals, in (list), not_in (list), matches (regex), not_matches (regex), contains, min (number), max (number).
Use real attribute names from the Terraform provider documentation.`

// RuleDraft is a validated proposal and its effect on the scanned files.
type RuleDraft struct {
	YAML  string      `json:"yaml"` // canonical YAML for one custom_rules item
	Rule  *CustomRule `json:"rule,omitempty"`
	Hits  []Finding   `json:"hits"` // findings the rule raises on the input
	Error string      `json:"error,omitempty"`
}

var (
	fenceRE   = regexp.MustCompile("(?s)```(?:ya?ml)?\\s*\\n(.*?)```")
	draftIDRE = regexp.MustCompile(`^[A-Z][A-Z0-9-]{2,39}$`)
)

// DraftRule accepts exactly one custom rule, so a draft can't add waivers or disable rules.
// It re-encodes the rule and dry-runs it against in.Files.
func DraftRule(proposal string, in Input) RuleDraft {
	text := strings.TrimSpace(proposal)
	if m := fenceRE.FindStringSubmatch(text); m != nil {
		text = m[1]
	}
	text = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(text), "custom_rules:"))
	var rules []CustomRule
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	var err error
	if strings.HasPrefix(text, "-") {
		err = dec.Decode(&rules)
	} else {
		var r CustomRule
		err = dec.Decode(&r)
		rules = []CustomRule{r}
	}
	if err != nil {
		return RuleDraft{Error: "not a valid custom rule: " + err.Error()}
	}
	if len(rules) != 1 {
		return RuleDraft{Error: fmt.Sprintf("expected exactly one rule, got %d", len(rules))}
	}
	r := rules[0]
	r.ID = strings.ToUpper(strings.TrimSpace(r.ID))
	switch {
	case !draftIDRE.MatchString(r.ID):
		return RuleDraft{Error: "id must be 3-40 uppercase letters, digits or dashes"}
	case strings.HasPrefix(r.ID, "TG-"):
		return RuleDraft{Error: "ids starting with TG- are reserved for built-in rules"}
	case len(r.ResourceTypes) == 0:
		return RuleDraft{Error: "resource_types is required so the rule cannot match everything by accident"}
	}
	if r.Title == "" {
		r.Title = r.ID
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode([]CustomRule{r}); err != nil {
		return RuleDraft{Error: err.Error()}
	}
	cfg := "custom_rules:\n" + indent(buf.String(), "  ")
	parsed, err := ParseConfig(cfg)
	if err != nil {
		return RuleDraft{Error: err.Error()}
	}
	d := RuleDraft{YAML: strings.TrimRight(indent(buf.String(), "  "), "\n"), Rule: &parsed.CustomRules[0], Hits: []Finding{}}
	if len(in.Files) > 0 {
		for _, f := range Scan(Input{Files: in.Files, Config: cfg}).Findings {
			if f.RuleID == r.ID {
				d.Hits = append(d.Hits, f)
			}
		}
		sort.SliceStable(d.Hits, func(i, j int) bool { return d.Hits[i].Resource < d.Hits[j].Resource })
	}
	return d
}

// ResourceTypes lists resource types only; that's all a model gets, never code.
func ResourceTypes(files map[string]string) []string {
	seen := map[string]bool{}
	for _, r := range Parse(files).Resources {
		seen[r.Type] = true
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func indent(s, pad string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = pad + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
