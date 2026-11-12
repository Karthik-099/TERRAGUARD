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
	// Baseline: FindingKeys accepted as existing debt (reported as waived).
	Baseline []string `json:"baseline,omitempty"`
	// Schema: optional terraform providers schema -json output.
	Schema string `json:"schema,omitempty"`
	// Extra are findings from outside the engine (Rego policies); they get the
	// same waivers, ignores and gate as built-in ones.
	Extra []Finding `json:"extra,omitempty"`
	// Coverage adds the per-resource list to Report.Coverage.
	Coverage bool `json:"coverage,omitempty"`
	// Frameworks limits the scan to these formats (terraform, kubernetes, ...); empty means all.
	Frameworks []string `json:"frameworks,omitempty"`
	// NoBuiltinSchema turns off the bundled provider schemas used when Schema is empty.
	NoBuiltinSchema bool `json:"no_builtin_schema,omitempty"`
	// GraphPolicies are extra policies in Checkov's YAML graph format.
	GraphPolicies []string `json:"graph_policies,omitempty"`
	// VarFiles are tfvars files passed explicitly, as with terraform -var-file.
	VarFiles []VarFile `json:"var_files,omitempty"`
	// Only and Skip select rules by ID or glob for this run (--check, --skip-check).
	Only []string `json:"only,omitempty"`
	Skip []string `json:"skip,omitempty"`
	// CodeOwners is the text of a CODEOWNERS file; every finding with a file
	// gets the owners of that file in Finding.CodeOwners.
	CodeOwners string `json:"code_owners,omitempty"`
	// CodeOwnersRoot is the Files key prefix (a directory) the CODEOWNERS
	// patterns are relative to; empty means the keys already are.
	CodeOwnersRoot string `json:"code_owners_root,omitempty"`
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
	Cost     *CostEstimate    `json:"cost,omitempty"` // offline estimate, only when the plan has priced resources
	// Dashboard aggregates over active findings.
	ByCategory map[string]int `json:"by_category"`
	ByProvider map[string]int `json:"by_provider"`
	Providers  map[string]int `json:"providers"` // resources per provider
	Compliance []Framework    `json:"compliance"`
	Errors     []string       `json:"errors,omitempty"`
	// Trace shows how the result was produced, stage by stage.
	Trace Trace `json:"trace"`
	// Coverage says what was checked: every resource, how many rules judged
	// it and which failed, and the resource types no rule covers.
	Coverage *Coverage `json:"coverage,omitempty"`
	// Frameworks counts the non-Terraform files read, by format.
	Frameworks map[string]int `json:"frameworks,omitempty"`
	// GateFailures explains every reason Passed is false.
	GateFailures []string `json:"gate_failures,omitempty"`
}

type Trace struct {
	ParseMs     float64 `json:"parse_ms"`
	ChecksMs    float64 `json:"checks_ms"`
	RulesMs     float64 `json:"rules_ms"`
	PolicyMs    float64 `json:"policy_ms"`
	Evaluations int     `json:"evaluations"` // rule x resource checks performed
	CustomRules int     `json:"custom_rules"`
}

func since(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }

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
	if strings.Contains(in.Config, packPrefix) { // built-in packs resolve anywhere, the browser included
		if merged, err := ResolveExtends(in.Config, nil); err == nil {
			in.Config = merged
		}
	}
	cfg, err := ParseConfig(in.Config)
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		cfg, _ = ParseConfig("")
	}
	if in.FailOn != "" {
		cfg.FailOn = ParseSeverity(in.FailOn)
	}
	cfg.Disable = append(cfg.Disable, in.Skip...)
	cfg.only = in.Only
	rep.FailOn = cfg.FailOn

	t := time.Now()
	files := in.Files
	if len(in.Frameworks) > 0 {
		files = map[string]string{}
		for name, src := range in.Files {
			if f := FormatOf(name, src); f == "" || contains(in.Frameworks, f) { // unknown files are skipped by Parse anyway
				files[name] = src
			}
		}
	}
	m := Parse(files, in.VarFiles...)
	rep.Frameworks = map[string]int{}
	for _, f := range m.Formats {
		rep.Frameworks[f]++
	}
	rep.Trace.ParseMs = since(t)
	t = time.Now()
	resources := m.Resources
	findings := moduleChecks(m)
	if strings.TrimSpace(in.Schema) != "" {
		if s, err := parseSchemas(in.Schema); err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		} else {
			findings = append(findings, schemaChecks(m, s)...)
		}
	} else if !in.NoBuiltinSchema {
		if s := builtinSchemaFor(m); s != nil {
			findings = append(findings, schemaChecksSkip(m, s, otherProvider(m))...)
		}
	}
	rep.Trace.ChecksMs = since(t)
	rep.Trace.CustomRules = len(cfg.CustomRules)
	if strings.TrimSpace(in.Plan) != "" {
		sum, planRes, planFindings, err := parsePlan(in.Plan)
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		} else {
			rep.Plan = sum
			if c, err := EstimateCost(in.Plan); err == nil && len(c.Lines) > 0 {
				rep.Cost = c
			}
			findings = append(findings, planFindings...)
			resources = append(resources, planRes...)
		}
	}

	t = time.Now()
	checks := make([]int, len(resources))   // rules that judged each resource
	specific := make([]int, len(resources)) // of those, rules written for its type
	enabled := func(id string) bool {
		return !globAny(cfg.Disable, id) && (len(cfg.only) == 0 || globAny(cfg.only, id))
	}
	for ri, r := range resources {
		for i := range Rules {
			rule := &Rules[i]
			if !rule.applies(r.Type) {
				continue
			}
			rep.Trace.Evaluations++
			if enabled(rule.ID) {
				checks[ri]++
				if len(rule.Types) > 0 {
					specific[ri]++
				}
			}
			for _, h := range rule.Check(r) {
				f := newFinding(rule.ID, h.Sev, h.Msg, r.Address, r.File, r.line(h.Path))
				src := r.via(h.Path)
				if h.Fix != nil && src == "" {
					src = r.via(strings.Join(h.Fix.Path, "."))
				}
				if src != "" {
					// Fix the variable's value, not the reference, so no auto-fix here.
					f.Message += " The value comes from " + src + "; change it where that is set."
					h.Fix = nil
				}
				if h.Fix != nil && !r.FromPlan && r.Format != "" {
					f.Fix = formatFix(r, h)
					h.Fix = nil
				}
				if h.Fix != nil && !r.FromPlan && r.Format == "" {
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
	gf, gerrs := graphScan(resources, in.GraphPolicies)
	findings = append(findings, gf...)
	findings = append(findings, in.Extra...)
	rep.Errors = append(rep.Errors, gerrs...)

	rep.Trace.RulesMs = since(t)
	t = time.Now()
	for i := range findings {
		if lines := m.JSONLines[findings[i].File]; lines != nil {
			// Point at the JSON source; hclwrite cannot edit JSON, so no auto-fix.
			findings[i].Line, findings[i].Fix = lines[findings[i].Line], nil
		}
	}
	// After the JSON line mapping: the secret scan reads the raw files and has its own lines.
	findings = supersedeOldSecrets(append(findings, secretScan(files)...))
	ignSrc := make(map[string][]byte, len(files)) // inline ignores also apply in files the parser did not keep
	for name, src := range files {
		ignSrc[name] = []byte(src)
	}
	for name, src := range m.Files {
		ignSrc[name] = src
	}
	blockLine := map[string]int{}
	for _, b := range m.Blocks {
		blockLine[b.Address()] = b.Line
	}
	findings = applyPolicy(findings, cfg, inlineIgnores(ignSrc, time.Now()), blockLine, time.Now())
	if len(in.Baseline) > 0 {
		accepted := map[string]bool{}
		for _, k := range in.Baseline {
			accepted[k] = true
		}
		for i := range findings {
			if !findings[i].Waived && accepted[FindingKey(findings[i])] && !globAny(cfg.Unwaivable, findings[i].RuleID) {
				findings[i].Waived, findings[i].WaiverReason = true, "accepted in baseline"
			}
		}
	}
	if in.CodeOwners != "" {
		co := ParseCodeOwners(in.CodeOwners)
		for i := range findings {
			findings[i].CodeOwners = co.OwnersUnder(in.CodeOwnersRoot, findings[i].File)
		}
	}
	sortFindings(findings)
	rep.Trace.PolicyMs = since(t)
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
	for ri, r := range resources { // graph policies judge resources too
		for i := range graphRules {
			if g := &graphRules[i]; g.applies(r.Type) && enabled(g.ID) {
				checks[ri]++
				specific[ri]++
			}
		}
	}
	rep.Coverage = buildCoverage(resources, checks, specific, rep.Findings, in.Coverage)
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

	rep.Stats = Stats{Files: len(in.Files), Resources: len(m.Resources), Rules: len(Rules) + len(ModuleRules) + len(secretRules) + len(cfg.CustomRules)}
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
	all := append(append(append(append(append([]Rule{}, Rules...), ModuleRules...), schemaRules...), graphRules...), secretRules...)
	for i := range all {
		all[i].Themes = ThemesFor(all[i].ID)
		all[i].Since = RuleSince(all[i].ID)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

// Coverage summarises what a scan checked.
type Coverage struct {
	Resources int                `json:"resources"`
	Covered   int                `json:"covered"`             // resources at least one rule written for their type judged
	Checks    int                `json:"checks"`              // rule evaluations
	Failed    int                `json:"failed"`              // evaluations with an active finding
	Passed    int                `json:"passed"`              // evaluations without one
	Uncovered []string           `json:"uncovered,omitempty"` // resource types no rule applies to
	Items     []ResourceCoverage `json:"items,omitempty"`
}

// ResourceCoverage is one resource's result.
type ResourceCoverage struct {
	Address string   `json:"address"`
	Type    string   `json:"type"`
	File    string   `json:"file"`
	Line    int      `json:"line"`
	Format  string   `json:"format,omitempty"`
	Checks  int      `json:"checks"`
	Failed  []string `json:"failed,omitempty"` // rule IDs with active findings
}

func buildCoverage(rs []*Resource, checks, specific []int, findings []Finding, items bool) *Coverage {
	failed := map[string]map[string]bool{}
	for _, f := range findings {
		if f.Waived || f.Resource == "" {
			continue
		}
		if failed[f.Resource] == nil {
			failed[f.Resource] = map[string]bool{}
		}
		failed[f.Resource][f.RuleID] = true
	}
	c := &Coverage{Resources: len(rs)}
	uncovered := map[string]bool{}
	for i, r := range rs {
		c.Checks += checks[i]
		if specific[i] > 0 {
			c.Covered++
		} else {
			uncovered[r.Type] = true
		}
		ids := sortedKeys(failed[r.Address])
		n := 0
		for _, id := range ids {
			if ri := ruleIndex[id]; ri != nil && ri.applies(r.Type) {
				n++ // only rules that judge resources; module checks are reported elsewhere
			}
		}
		c.Failed += min(n, checks[i])
		if items {
			c.Items = append(c.Items, ResourceCoverage{Address: r.Address, Type: r.Type, File: r.File, Line: r.Line, Format: r.Format, Checks: checks[i], Failed: ids})
		}
	}
	c.Passed = c.Checks - c.Failed
	c.Uncovered = sortedKeys(uncovered)
	return c
}

// formatFix places a rule's fix in a non-Terraform file, or drops it when that
// format has no safe editor yet.
func formatFix(r *Resource, h Hit) *Fix {
	fx := *h.Fix
	fx.File = r.File
	switch r.Format {
	case FormatKubernetes:
		fx.Format, fx.Doc, fx.Root = FormatKubernetes, r.Doc, r.Root
		// The hit's path names the exact container (container.1); the fix's path names the setting.
		if hp := strings.Split(h.Path, "."); len(hp) > 1 {
			bare := strings.Split(stripIndexes(h.Path), ".")
			if len(fx.Path) >= len(bare) && strings.Join(fx.Path[:len(bare)], ".") == strings.Join(bare, ".") {
				fx.Path = append(hp, fx.Path[len(bare):]...)
			}
		}
		return &fx
	case FormatDockerfile:
		if fx.Format == FormatDockerfile && fx.Line > 0 {
			return &fx
		}
	}
	return nil
}
