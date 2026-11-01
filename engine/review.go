package engine

import (
	"fmt"
	"sort"
	"strings"
)

// Review judges a change by what it introduces.
type Review struct {
	Tier         string    `json:"tier"` // trivial | lite | full
	ChangedFiles []string  `json:"changed_files"`
	New          []Finding `json:"new"`
	Resolved     []Finding `json:"resolved"`
	Existing     int       `json:"existing"`
	Passed       bool      `json:"passed"`
	FailOn       Severity  `json:"fail_on"`
}

// FindingKey ignores line numbers, which shift with unrelated edits.
func FindingKey(f Finding) string {
	k := f.RuleID + "|" + f.File + "|" + f.Resource
	if f.Resource == "" {
		k += "|" + f.Message
	}
	return k
}

func NewReview(base, head *Report, changed []string) *Review {
	r := &Review{ChangedFiles: changed, FailOn: head.FailOn, New: []Finding{}, Resolved: []Finding{}}
	inBase, inHead := map[string]bool{}, map[string]bool{}
	for _, f := range base.Findings {
		if !f.Waived {
			inBase[FindingKey(f)] = true
		}
	}
	for _, f := range head.Findings {
		if f.Waived {
			continue
		}
		inHead[FindingKey(f)] = true
		if inBase[FindingKey(f)] {
			r.Existing++
		} else {
			r.New = append(r.New, f)
		}
	}
	for _, f := range base.Findings {
		if !f.Waived && !inHead[FindingKey(f)] {
			r.Resolved = append(r.Resolved, f)
		}
	}
	sortFindings(r.New)
	sortFindings(r.Resolved)

	r.Passed = true
	r.Tier = "lite"
	if len(changed) == 0 {
		r.Tier = "trivial"
	}
	for _, f := range r.New {
		if f.Blocking || (r.FailOn != "NONE" && f.Severity.Rank() >= r.FailOn.Rank()) {
			r.Passed = false
		}
		if f.Blocking || f.Severity.Rank() >= High.Rank() || f.Category == CatPlan {
			r.Tier = "full"
		}
	}
	return r
}

// reviewLevel uses review vocabulary instead of scanner severities.
func reviewLevel(f Finding) string {
	switch {
	case f.Blocking || f.Severity == Critical:
		return "Critical"
	case f.Severity == High:
		return "Important"
	case f.Severity == Medium:
		return "Suggestion"
	}
	return "Nit"
}

func reviewSection(f Finding) string {
	switch {
	case f.RuleID == "TG-TF-004":
		return "Documentation"
	case f.Category == CatSecurity || f.Category == CatAttackPath:
		return "Security"
	case f.Category == CatPolicy || f.Category == CatBestPrac:
		return "Codex compliance"
	case f.Category == CatCost:
		return "Cost"
	}
	return "Release impact" // validate, plan, reliability
}

var sectionOrder = []string{"Security", "Release impact", "Codex compliance", "Cost", "Documentation"}

func (r *Review) Markdown() string {
	var b strings.Builder
	status := "passed"
	if !r.Passed {
		status = "changes requested"
	}
	fmt.Fprintf(&b, "## TerraGuard review: %s (%s risk tier)\n\n", status, r.Tier)
	fmt.Fprintf(&b, "%d changed Terraform file(s) · %d new finding(s) · %d resolved · %d pre-existing, not introduced by this change.\n\n",
		len(r.ChangedFiles), len(r.New), len(r.Resolved), r.Existing)
	if r.Tier == "trivial" {
		b.WriteString("No Terraform changes to review.\n")
		return b.String()
	}
	if len(r.New) == 0 {
		b.WriteString("This change introduces no new findings.\n")
	}
	bySection := map[string][]Finding{}
	for _, f := range r.New {
		bySection[reviewSection(f)] = append(bySection[reviewSection(f)], f)
	}
	for _, sec := range sectionOrder {
		fs := bySection[sec]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s\n\n", sec)
		for _, f := range fs {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(&b, "- **%s** `%s` `%s`: %s. %s", reviewLevel(f), f.RuleID, loc, f.Title, f.Message)
			if f.Remediation != "" {
				fmt.Fprintf(&b, " Fix: %s", f.Remediation)
			}
			if f.Fix != nil {
				b.WriteString(" (auto-fixable: `terraguard fix`)")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(r.Resolved) > 0 {
		b.WriteString("### Resolved in this change\n\n")
		for _, f := range r.Resolved {
			fmt.Fprintf(&b, "- `%s` %s (%s)\n", f.RuleID, f.Title, orDash(f.Resource))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ChangedTerraform filters a list of paths to Terraform sources and policy.
func ChangedTerraform(paths []string) []string {
	var out []string
	for _, p := range paths {
		if strings.HasSuffix(p, ".tf") || strings.HasSuffix(p, ".tfvars") || strings.HasSuffix(p, ".terraguard.yml") || strings.HasSuffix(p, ".terraguard.yaml") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
