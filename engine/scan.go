package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type Input struct {
	Files  map[string]string `json:"files"`
	Plan   string            `json:"plan,omitempty"`    // terraform show -json output
	Config string            `json:"config,omitempty"`  // .terraguard.yml contents
	FailOn string            `json:"fail_on,omitempty"` // overrides config fail_on
	// Baseline lists FindingKey values accepted as existing debt: they are
	// reported as waived so the gate fails only on new findings.
	Baseline []string `json:"baseline,omitempty"`
}

type Report struct {
	Version  string           `json:"version"`
	Passed   bool             `json:"passed"`
	FailOn   Severity         `json:"fail_on"`
	Score    int              `json:"score"`
	Grade    string           `json:"grade"`
	Verdict  Verdict          `json:"verdict"`
	Summary  map[Severity]int `json:"summary"`
	Waived   int              `json:"waived"`
	Fixable  int              `json:"fixable"`
	Stats    Stats            `json:"stats"`
	Findings []Finding        `json:"findings"`
	Graph    Graph            `json:"graph"`
	Plan     *PlanSummary     `json:"plan,omitempty"`
	// Dashboard aggregates over active findings.
	ByCategory map[string]int `json:"by_category"`
	ByProvider map[string]int `json:"by_provider"`
	Providers  map[string]int `json:"providers"` // resources per provider
	Compliance []Framework    `json:"compliance"`
	Errors     []string       `json:"errors,omitempty"`
	// GateFailures explains every reason Passed is false.
	GateFailures []string `json:"gate_failures,omitempty"`
}

// Verdict answers "will terraform apply succeed?" from static evidence.
type Verdict struct {
	WillApply bool   `json:"will_apply"`
	Blocking  int    `json:"blocking"`
	Message   string `json:"message"`
}

type Stats struct {
	Files     int `json:"files"`
	Resources int `json:"resources"`
	Rules     int `json:"rules"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Node struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Severity Severity `json:"severity,omitempty"`
	Findings int      `json:"findings"`
}

type Edge struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

var weights = map[Severity]int{Critical: 20, High: 8, Medium: 3, Low: 1}

func Scan(in Input) *Report {
	rep := &Report{Version: Version, Summary: map[Severity]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}}
	cfg, err := ParseConfig(in.Config)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		cfg, _ = ParseConfig("")
	}
	if in.FailOn != "" {
		cfg.FailOn = ParseSeverity(in.FailOn)
	}
	rep.FailOn = cfg.FailOn

	m := Parse(in.Files)
	resources := m.Resources
	findings := moduleChecks(m)
	if strings.TrimSpace(in.Plan) != "" {
		sum, planRes, planFindings, err := parsePlan(in.Plan)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		} else {
			rep.Plan = sum
			findings = append(findings, planFindings...)
			resources = append(resources, planRes...)
		}
	}

	for _, r := range resources {
		for i := range Rules {
			rule := &Rules[i]
			if !rule.applies(r.Type) {
				continue
			}
			for _, h := range rule.Check(r) {
				f := newFinding(rule.ID, h.Sev, h.Msg, r.Address, r.File, r.line(h.Path))
				if h.Fix != nil && !r.FromPlan {
					fx := *h.Fix
					fx.File = r.File
					fx.Block = "resource." + r.Type + "." + r.Name
					if r.Mode == "data" {
						fx.Block = "data." + r.Type + "." + r.Name
					}
					f.Fix = &fx
				}
				findings = append(findings, f)
			}
		}
		for i := range cfg.CustomRules {
			cr := &cfg.CustomRules[i]
			if msg, bad := cr.check(r); bad {
				findings = append(findings, Finding{RuleID: cr.ID, Severity: cr.Severity, Category: CatPolicy, Title: cr.Title,
					Message: r.Address + ": " + msg, Resource: r.Address, File: r.File, Line: r.line(cr.Attribute), Remediation: cr.Remediation,
					Owner: cr.Owner, Docs: cr.DocsURL})
			}
		}
	}

	blockLine := map[string]int{}
	for _, b := range m.Blocks {
		blockLine[b.Address()] = b.Line
	}
	findings = applyPolicy(findings, cfg, inlineIgnores(m.Files), blockLine, time.Now())
	if len(in.Baseline) > 0 {
		accepted := map[string]bool{}
		for _, k := range in.Baseline {
			accepted[k] = true
		}
		for i := range findings {
			if !findings[i].Waived && accepted[FindingKey(findings[i])] {
				findings[i].Waived, findings[i].WaiverReason = true, "accepted in baseline"
			}
		}
	}
	sortFindings(findings)
	rep.Findings = findings
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}

	score := 100
	rep.ByCategory, rep.ByProvider, rep.Providers = map[string]int{}, map[string]int{}, map[string]int{}
	for _, r := range resources {
		if p := providerOf(r.Address); p != "" {
			rep.Providers[p]++
		}
	}
	activeBlocking := 0
	for _, f := range findings {
		// A waiver accepts a risk; it does not make terraform apply succeed.
		if f.Blocking {
			rep.Verdict.Blocking++
		}
		if f.Waived {
			rep.Waived++
			continue
		}
		rep.Summary[f.Severity]++
		rep.ByCategory[f.Category]++
		if p := providerOf(f.Resource); p != "" {
			rep.ByProvider[p]++
		}
		score -= weights[f.Severity]
		if f.Blocking {
			activeBlocking++
		}
		if f.Fix != nil {
			rep.Fixable++
		}
	}
	rep.Score = max(score, 0)
	rep.Grade = grade(rep.Score)
	if activeBlocking > 0 {
		rep.GateFailures = append(rep.GateFailures, fmt.Sprintf("%d finding(s) would make terraform apply fail", activeBlocking))
	}
	if cfg.FailOn != "NONE" {
		n := 0
		for _, f := range findings {
			if !f.Waived && f.Severity.Rank() >= cfg.FailOn.Rank() {
				n++
			}
		}
		if n > 0 {
			rep.GateFailures = append(rep.GateFailures, fmt.Sprintf("%d active finding(s) at or above fail_on %s", n, cfg.FailOn))
		}
	}
	for _, sev := range []Severity{Critical, High, Medium, Low, Info} {
		if limit, ok := cfg.MaxFindings[sev]; ok && rep.Summary[sev] > limit {
			rep.GateFailures = append(rep.GateFailures, fmt.Sprintf("%d %s finding(s) exceed the budget of %d", rep.Summary[sev], sev, limit))
		}
	}
	rep.Passed = len(rep.GateFailures) == 0
	rep.Verdict.WillApply = rep.Verdict.Blocking == 0 && len(in.Files) > 0
	switch {
	case len(in.Files) == 0:
		rep.Verdict.Message = "No Terraform files to evaluate."
	case rep.Verdict.Blocking > 0:
		rep.Verdict.Message = fmt.Sprintf("terraform validate/apply is expected to FAIL: %d blocking issue(s).", rep.Verdict.Blocking)
	default:
		rep.Verdict.Message = "No blocking issues found; syntax, references and provider-side validations look applyable."
	}

	rep.Stats = Stats{Files: len(in.Files), Resources: len(m.Resources), Rules: len(Rules) + len(ModuleRules) + len(cfg.CustomRules)}
	rep.Graph = buildGraph(m, findings)
	rep.Compliance = complianceReport(findings)
	return rep
}

func grade(s int) string {
	switch {
	case s >= 90:
		return "A"
	case s >= 75:
		return "B"
	case s >= 60:
		return "C"
	case s >= 40:
		return "D"
	}
	return "F"
}

func buildGraph(m *Module, fs []Finding) Graph {
	g := Graph{Nodes: []Node{}, Edges: []Edge{}}
	nodes := map[string]*Node{}
	for _, b := range m.Blocks {
		if (b.Kind != "resource" && b.Kind != "data" && b.Kind != "module") || len(b.Labels) == 0 {
			continue
		}
		typ := b.Labels[0]
		if b.Kind == "module" {
			typ = "module"
		}
		g.Nodes = append(g.Nodes, Node{ID: b.Address(), Type: typ, File: b.File, Line: b.Line})
	}
	for i := range g.Nodes {
		nodes[g.Nodes[i].ID] = &g.Nodes[i]
	}
	for _, f := range fs {
		if n := nodes[f.Resource]; n != nil && !f.Waived {
			n.Findings++
			if f.Severity.Rank() > n.Severity.Rank() {
				n.Severity = f.Severity
			}
		}
	}
	seen := map[string]bool{}
	for _, b := range m.Blocks {
		src := b.Address()
		if nodes[src] == nil {
			continue
		}
		for _, r := range b.Refs {
			if nodes[r.Addr] != nil && r.Addr != src && !seen[src+">"+r.Addr] {
				seen[src+">"+r.Addr] = true
				g.Edges = append(g.Edges, Edge{Source: src, Target: r.Addr})
			}
		}
	}
	return g
}

// FixAll applies every machine fix for active findings.
func FixAll(in Input) (map[string]string, []error) {
	var fixes []*Fix
	for _, f := range Scan(in).Findings {
		if f.Fix != nil && !f.Waived {
			fixes = append(fixes, f.Fix)
		}
	}
	return ApplyFixes(in.Files, fixes)
}

// Catalog lists every built-in rule, sorted by ID.
func Catalog() []Rule {
	all := append(append([]Rule{}, Rules...), ModuleRules...)
	for i := range all {
		all[i].Themes = ThemesFor(all[i].ID)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}
