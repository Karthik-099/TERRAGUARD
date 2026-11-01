// Package pulse: control adoption, expiring waivers and trend across modules.
package pulse

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// Module is one scanned Terraform root or child module.
type Module struct {
	Path      string
	Report    *engine.Report
	Config    *engine.Config
	HasPolicy bool
}

// Control is an engineering standard measured on every module.
type Control struct {
	ID    string
	Title string
	Pass  func(m Module) bool
}

func hasRule(m Module, ids ...string) bool {
	for _, f := range m.Report.Findings {
		if f.Waived {
			continue
		}
		for _, id := range ids {
			if f.RuleID == id {
				return true
			}
		}
	}
	return false
}

var Controls = []Control{
	{"policy", "Policy-as-code file present", func(m Module) bool { return m.HasPolicy }},
	{"gate", "Passes the policy gate", func(m Module) bool { return m.Report.Passed }},
	{"applies", "No apply-blocking issues", func(m Module) bool { return m.Report.Verdict.WillApply }},
	{"pinned", "Provider and module versions pinned", func(m Module) bool { return !hasRule(m, "TG-TF-001", "TG-TF-002") }},
	{"state", "Remote state, encrypted and locked", func(m Module) bool { return !hasRule(m, "TG-STATE-001", "TG-STATE-002", "TG-STATE-003") }},
	{"secrets", "No hardcoded secrets", func(m Module) bool { return !hasRule(m, "TG-SEC-001", "TG-SEC-002") }},
}

type ModuleRow struct {
	Path      string          `json:"path"`
	Grade     string          `json:"grade"`
	Score     int             `json:"score"`
	Resources int             `json:"resources"`
	Findings  int             `json:"findings"`
	Critical  int             `json:"critical"`
	High      int             `json:"high"`
	Blocking  int             `json:"blocking"`
	Controls  map[string]bool `json:"controls"`
}

type Adoption struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Passing int    `json:"passing"`
	Total   int    `json:"total"`
	Percent int    `json:"percent"`
}

type RuleCount struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Count   int    `json:"count"`
	Modules int    `json:"modules"`
}

type Waiver struct {
	Module     string `json:"module"`
	Rule       string `json:"rule"`
	Resource   string `json:"resource"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
	Expires    string `json:"expires"`
	Status     string `json:"status"` // expired | expiring | active | no-expiry
	DaysLeft   int    `json:"days_left"`
}

type Totals struct {
	Modules   int `json:"modules"`
	Resources int `json:"resources"`
	Findings  int `json:"findings"`
	AvgScore  int `json:"avg_score"`
}

type Delta struct {
	AvgScore int            `json:"avg_score"`
	Findings int            `json:"findings"`
	Adoption map[string]int `json:"adoption"` // percentage points
}

type Result struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Totals      Totals      `json:"totals"`
	Adoption    []Adoption  `json:"adoption"`
	Modules     []ModuleRow `json:"modules"`
	TopRules    []RuleCount `json:"top_rules"`
	Waivers     []Waiver    `json:"waivers"`
	Delta       *Delta      `json:"delta,omitempty"`
}

// ExpiringWithin is how far ahead a waiver counts as "expiring".
const ExpiringWithin = 30 * 24 * time.Hour

func Build(mods []Module, now time.Time, baseline *Result) *Result {
	r := &Result{GeneratedAt: now.UTC(), Modules: []ModuleRow{}, Waivers: []Waiver{}, TopRules: []RuleCount{}}
	passing := map[string]int{}
	ruleCount, ruleMods, ruleTitle := map[string]int{}, map[string]int{}, map[string]string{}
	scoreSum := 0
	for _, m := range mods {
		row := ModuleRow{Path: m.Path, Grade: m.Report.Grade, Score: m.Report.Score, Resources: m.Report.Stats.Resources,
			Blocking: m.Report.Verdict.Blocking, Controls: map[string]bool{}}
		seen := map[string]bool{}
		for _, f := range m.Report.Findings {
			if f.Waived {
				continue
			}
			row.Findings++
			switch f.Severity {
			case engine.Critical:
				row.Critical++
			case engine.High:
				row.High++
			}
			ruleCount[f.RuleID]++
			ruleTitle[f.RuleID] = f.Title
			if !seen[f.RuleID] {
				seen[f.RuleID] = true
				ruleMods[f.RuleID]++
			}
		}
		for _, c := range Controls {
			ok := c.Pass(m)
			row.Controls[c.ID] = ok
			if ok {
				passing[c.ID]++
			}
		}
		if m.Config != nil {
			for _, w := range m.Config.Waivers {
				r.Waivers = append(r.Waivers, waiverRow(m.Path, w, now))
			}
		}
		r.Modules = append(r.Modules, row)
		r.Totals.Resources += row.Resources
		r.Totals.Findings += row.Findings
		scoreSum += row.Score
	}
	r.Totals.Modules = len(mods)
	if len(mods) > 0 {
		r.Totals.AvgScore = scoreSum / len(mods)
	}
	for _, c := range Controls {
		a := Adoption{ID: c.ID, Title: c.Title, Passing: passing[c.ID], Total: len(mods)}
		if a.Total > 0 {
			a.Percent = a.Passing * 100 / a.Total
		}
		r.Adoption = append(r.Adoption, a)
	}
	for id, n := range ruleCount {
		r.TopRules = append(r.TopRules, RuleCount{ID: id, Title: ruleTitle[id], Count: n, Modules: ruleMods[id]})
	}
	sort.Slice(r.TopRules, func(i, j int) bool {
		a, b := r.TopRules[i], r.TopRules[j]
		if a.Modules != b.Modules {
			return a.Modules > b.Modules
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
	if len(r.TopRules) > 10 {
		r.TopRules = r.TopRules[:10]
	}
	sort.Slice(r.Modules, func(i, j int) bool {
		return r.Modules[i].Score < r.Modules[j].Score || (r.Modules[i].Score == r.Modules[j].Score && r.Modules[i].Path < r.Modules[j].Path)
	})
	order := map[string]int{"expired": 0, "expiring": 1, "no-expiry": 2, "active": 3}
	sort.SliceStable(r.Waivers, func(i, j int) bool {
		if order[r.Waivers[i].Status] != order[r.Waivers[j].Status] {
			return order[r.Waivers[i].Status] < order[r.Waivers[j].Status]
		}
		return r.Waivers[i].DaysLeft < r.Waivers[j].DaysLeft
	})
	if baseline != nil {
		d := &Delta{AvgScore: r.Totals.AvgScore - baseline.Totals.AvgScore, Findings: r.Totals.Findings - baseline.Totals.Findings, Adoption: map[string]int{}}
		prev := map[string]int{}
		for _, a := range baseline.Adoption {
			prev[a.ID] = a.Percent
		}
		for _, a := range r.Adoption {
			d.Adoption[a.ID] = a.Percent - prev[a.ID]
		}
		r.Delta = d
	}
	return r
}

func waiverRow(module string, w engine.Waiver, now time.Time) Waiver {
	row := Waiver{Module: module, Rule: w.Rule, Resource: w.Resource, Reason: w.Reason, ApprovedBy: w.ApprovedBy, Expires: w.Expires}
	exp, err := time.Parse("2006-01-02", w.Expires)
	switch {
	case w.Expires == "" || err != nil:
		row.Status = "no-expiry"
	default:
		left := exp.Add(24 * time.Hour).Sub(now) // a waiver is valid through its expiry date
		row.DaysLeft = int(left.Hours() / 24)
		switch {
		case left <= 0:
			row.Status = "expired"
		case left <= ExpiringWithin:
			row.Status = "expiring"
		default:
			row.Status = "active"
		}
	}
	return row
}

func signed(n int) string {
	if n > 0 {
		return fmt.Sprintf("+%d", n)
	}
	return fmt.Sprint(n)
}

// Markdown renders the report for a job summary, PR comment or wiki page.
func Markdown(r *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## TerraGuard Pulse\n\n%d modules, %d resources, %d active findings, average score %d/100. Generated %s.\n\n",
		r.Totals.Modules, r.Totals.Resources, r.Totals.Findings, r.Totals.AvgScore, r.GeneratedAt.Format("2006-01-02 15:04 UTC"))
	if d := r.Delta; d != nil {
		fmt.Fprintf(&b, "Change since baseline: average score %s, findings %s.\n\n", signed(d.AvgScore), signed(d.Findings))
	}
	b.WriteString("### Control adoption\n\n| Control | Modules passing | Adoption |")
	if r.Delta != nil {
		b.WriteString(" Change |")
	}
	b.WriteString("\n|---|---|---|")
	if r.Delta != nil {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, a := range r.Adoption {
		fmt.Fprintf(&b, "| %s | %d / %d | %d%% |", a.Title, a.Passing, a.Total, a.Percent)
		if r.Delta != nil {
			fmt.Fprintf(&b, " %s pts |", signed(r.Delta.Adoption[a.ID]))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n### Modules (lowest score first)\n\n| Module | Grade | Score | Findings | Critical | High | Blocks apply | Controls met |\n|---|---|---|---|---|---|---|---|\n")
	for _, m := range r.Modules {
		met := 0
		for _, ok := range m.Controls {
			if ok {
				met++
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s | %d | %d | %d | %d | %d | %d / %d |\n", m.Path, m.Grade, m.Score, m.Findings, m.Critical, m.High, m.Blocking, met, len(Controls))
	}
	if len(r.TopRules) > 0 {
		b.WriteString("\n### Most common issues\n\n| Rule | Title | Modules | Occurrences |\n|---|---|---|---|\n")
		for _, t := range r.TopRules {
			fmt.Fprintf(&b, "| `%s` | %s | %d | %d |\n", t.ID, t.Title, t.Modules, t.Count)
		}
	}
	if len(r.Waivers) > 0 {
		b.WriteString("\n### Waivers\n\n| Status | Module | Rule | Resource | Expires | Approved by | Reason |\n|---|---|---|---|---|---|---|\n")
		for _, w := range r.Waivers {
			exp := w.Expires
			if w.Status == "expiring" || w.Status == "active" {
				exp = fmt.Sprintf("%s (%d days)", w.Expires, w.DaysLeft)
			}
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %s | %s |\n", w.Status, w.Module, w.Rule, orDash(w.Resource), orDash(exp), orDash(w.ApprovedBy), orDash(w.Reason))
		}
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, "|", "\\|")
}
