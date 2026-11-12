package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

var sarifLevel = map[Severity]string{Critical: "error", High: "error", Medium: "warning", Low: "note", Info: "note"}
var secScore = map[Severity]string{Critical: "9.5", High: "8.0", Medium: "5.5", Low: "3.0", Info: "1.0"}

// SARIF renders SARIF 2.1.0 for GitHub code scanning (inline PR annotations).
func SARIF(r *Report) ([]byte, error) {
	type obj = map[string]any
	var rules []obj
	ruleIdx := map[string]int{}
	var results []obj
	seenKey := map[string]int{}
	for _, f := range r.Findings {
		key := FindingKey(f)
		if n := seenKey[key]; n > 0 { // the same rule twice on one resource stays two alerts
			key = fmt.Sprintf("%s#%d", key, n)
		}
		seenKey[FindingKey(f)]++
		if _, ok := ruleIdx[f.RuleID]; !ok {
			ruleIdx[f.RuleID] = len(rules)
			tags := []string{f.Category}
			if f.CWE != "" {
				tags = append(tags, f.CWE)
			}
			rules = append(rules, obj{
				"id": f.RuleID, "name": f.RuleID, "shortDescription": obj{"text": f.Title},
				"help":       obj{"text": f.Remediation, "markdown": "**Fix:** " + f.Remediation},
				"properties": obj{"tags": tags, "security-severity": secScore[f.Severity]},
			})
		}
		loc := obj{"physicalLocation": obj{"artifactLocation": obj{"uri": f.File}, "region": obj{"startLine": max(f.Line, 1)}}}
		res := obj{"ruleId": f.RuleID, "ruleIndex": ruleIdx[f.RuleID], "level": sarifLevel[f.Severity],
			"message": obj{"text": f.Message}, "locations": []obj{loc},
			// Line-independent, so moving code does not turn a finding into a new alert.
			"partialFingerprints": obj{"terraguardFindingKey/v1": fingerprint(key)}}
		if len(f.CodeOwners) > 0 {
			res["properties"] = obj{"code_owners": f.CodeOwners}
		}
		if f.Waived {
			res["suppressions"] = []obj{{"kind": "external", "justification": f.WaiverReason}}
		}
		results = append(results, res)
	}
	if results == nil {
		results = []obj{}
	}
	return json.MarshalIndent(obj{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []obj{{
			"tool":    obj{"driver": obj{"name": "TerraGuard", "version": Version, "informationUri": "https://github.com/Karthik-099/TERRAGUARD", "rules": rules}},
			"results": results,
		}},
	}, "", "  ")
}

// Markdown renders a PR-comment report.
func Markdown(r *Report) string { return markdown(r, false) }

// MarkdownByOwner is Markdown with findings in one section per code owner, unowned last.
func MarkdownByOwner(r *Report) string { return markdown(r, true) }

func markdownTable(b *strings.Builder, fs []Finding) {
	owners := false
	for _, f := range fs {
		owners = owners || len(f.CodeOwners) > 0
	}
	if owners {
		b.WriteString("| Severity | Rule | Location | Owners | Finding |\n|---|---|---|---|---|\n")
	} else {
		b.WriteString("| Severity | Rule | Location | Finding |\n|---|---|---|---|\n")
	}
	for i, f := range fs {
		if i == 50 {
			fmt.Fprintf(b, "\n…and %d more. See the SARIF results in the Security tab.\n", len(fs)-50)
			break
		}
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		own := ""
		if owners {
			own = orDash(strings.Join(f.CodeOwners, " ")) + " | "
		}
		fmt.Fprintf(b, "| %s | `%s` | `%s` | %s**%s**: %s |\n", f.Severity, f.RuleID, loc, own, f.Title, strings.ReplaceAll(f.Message, "|", "\\|"))
	}
}

func markdown(r *Report, byOwner bool) string {
	var b strings.Builder
	status := "Passed"
	if !r.Passed {
		status = "Failed"
	}
	fmt.Fprintf(&b, "## TerraGuard: %s (grade %s, score %d/100)\n\n", status, r.Grade, r.Score)
	apply := "Yes. " + r.Verdict.Message
	if !r.Verdict.WillApply {
		apply = "No. " + r.Verdict.Message
	}
	fmt.Fprintf(&b, "**Will it apply?** %s\n\n", apply)
	if c := r.Coverage; c != nil && c.Resources > 0 {
		fmt.Fprintf(&b, "**Coverage:** %s\n\n", coverageLine(c))
	}
	fmt.Fprintf(&b, "| Critical | High | Medium | Low | Info | Waived | Auto-fixable |\n|---|---|---|---|---|---|---|\n| %d | %d | %d | %d | %d | %d | %d |\n\n",
		r.Summary[Critical], r.Summary[High], r.Summary[Medium], r.Summary[Low], r.Summary[Info], r.Waived, r.Fixable)
	if p := r.Plan; p != nil {
		fmt.Fprintf(&b, "**Plan:** %d to add, %d to change, %d to destroy, %d to replace", p.Create, p.Update, p.Delete, p.Replace)
		if p.Import+p.Moved > 0 {
			fmt.Fprintf(&b, ", %d to import, %d moved", p.Import, p.Moved)
		}
		b.WriteString(".")
		if len(p.Drift) > 0 {
			fmt.Fprintf(&b, " **%d resource(s) drifted** from their code.", len(p.Drift))
		}
		if len(p.Outputs) > 0 {
			fmt.Fprintf(&b, " %d output(s) change.", len(p.Outputs))
		}
		b.WriteString("\n\n")
	}
	if c := r.Cost; c != nil {
		fmt.Fprintf(&b, "**Estimated monthly cost:** %s to %s (%s, fixed charges only; %s).\n\n", money(c.Before), money(c.After), signed(c.Delta()), c.Basis)
	}
	var active []Finding
	for _, f := range r.Findings {
		if !f.Waived {
			active = append(active, f)
		}
	}
	switch {
	case len(active) == 0:
		b.WriteString("No active findings.\n")
	case byOwner:
		for _, g := range GroupByOwner(active) {
			fmt.Fprintf(&b, "### %s (%d)\n\n", g.Owner, len(g.Findings))
			markdownTable(&b, g.Findings)
			b.WriteString("\n")
		}
	default:
		markdownTable(&b, active)
	}
	if r.Fixable > 0 {
		fmt.Fprintf(&b, "\n%d finding(s) can be fixed automatically: `terraguard fix .`\n", r.Fixable)
	}
	for _, g := range r.GateFailures {
		fmt.Fprintf(&b, "\n> Gate: %s\n", g)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "\n> Warning: %s\n", e)
	}
	return b.String()
}

// Text renders a terminal report.
func Text(r *Report) string { return text(r, false) }

// TextByOwner is Text with findings in one section per code owner, unowned last.
func TextByOwner(r *Report) string { return text(r, true) }

func textFinding(b *strings.Builder, f Finding) {
	loc := f.File
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	block := ""
	if f.Blocking {
		block = " [blocks apply]"
	}
	fmt.Fprintf(b, "%-8s %-15s %s%s\n         %s\n         %s\n", f.Severity, f.RuleID, loc, block, f.Title+": "+f.Message, "fix: "+f.Remediation)
}

func text(r *Report, byOwner bool) string {
	var b strings.Builder
	var active []Finding
	for _, f := range r.Findings {
		if !f.Waived {
			active = append(active, f)
		}
	}
	if byOwner {
		for _, g := range GroupByOwner(active) {
			fmt.Fprintf(&b, "== %s: %d finding(s) ==\n", g.Owner, len(g.Findings))
			for _, f := range g.Findings {
				textFinding(&b, f)
			}
			b.WriteString("\n")
		}
	} else {
		for _, f := range active {
			textFinding(&b, f)
		}
	}
	fmt.Fprintf(&b, "\n%s\nScore %d/100 (%s) · %d critical · %d high · %d medium · %d low · %d info · %d waived · %d auto-fixable\n",
		r.Verdict.Message, r.Score, r.Grade, r.Summary[Critical], r.Summary[High], r.Summary[Medium], r.Summary[Low], r.Summary[Info], r.Waived, r.Fixable)
	if c := r.Coverage; c != nil && c.Resources > 0 {
		b.WriteString(coverageLine(c) + "\n")
		for _, it := range c.Items {
			status := "ok  "
			if len(it.Failed) > 0 {
				status = "FAIL"
			} else if it.Checks == 0 {
				status = "none"
			}
			fmt.Fprintf(&b, "  %s %-60s %3d checks  %s\n", status, it.Address, it.Checks, strings.Join(it.Failed, " "))
		}
	}
	for _, g := range r.GateFailures {
		fmt.Fprintf(&b, "gate: %s\n", g)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "warning: %s\n", e)
	}
	return b.String()
}

// JUnit: one test case per active finding.
func JUnit(r *Report) ([]byte, error) {
	type failure struct {
		Message string `xml:"message,attr"`
		Type    string `xml:"type,attr"`
		Body    string `xml:",chardata"`
	}
	type testcase struct {
		Name      string   `xml:"name,attr"`
		Classname string   `xml:"classname,attr"`
		Failure   *failure `xml:"failure,omitempty"`
	}
	type testsuite struct {
		XMLName  xml.Name   `xml:"testsuite"`
		Name     string     `xml:"name,attr"`
		Tests    int        `xml:"tests,attr"`
		Failures int        `xml:"failures,attr"`
		Cases    []testcase `xml:"testcase"`
	}
	ts := testsuite{Name: "terraguard"}
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		ts.Cases = append(ts.Cases, testcase{Name: f.RuleID + " " + f.Title, Classname: loc,
			Failure: &failure{Message: f.Message, Type: string(f.Severity), Body: "Fix: " + f.Remediation}})
	}
	if len(ts.Cases) == 0 {
		ts.Cases = []testcase{{Name: "no active findings", Classname: "terraguard"}}
	}
	ts.Tests = len(ts.Cases)
	for _, c := range ts.Cases {
		if c.Failure != nil {
			ts.Failures++
		}
	}
	b, err := xml.MarshalIndent(ts, "", "  ")
	return append([]byte(xml.Header), b...), err
}

var cqSeverity = map[Severity]string{Critical: "critical", High: "major", Medium: "minor", Low: "info", Info: "info"}

// CodeQuality: GitLab's merge request report format.
func CodeQuality(r *Report) ([]byte, error) {
	type lines struct {
		Begin int `json:"begin"`
	}
	type location struct {
		Path  string `json:"path"`
		Lines lines  `json:"lines"`
	}
	type issue struct {
		Description string   `json:"description"`
		CheckName   string   `json:"check_name"`
		Fingerprint string   `json:"fingerprint"`
		Severity    string   `json:"severity"`
		Location    location `json:"location"`
	}
	out := []issue{}
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		sev := cqSeverity[f.Severity]
		if f.Blocking {
			sev = "blocker"
		}
		sum := sha256.Sum256([]byte(FindingKey(f)))
		out = append(out, issue{Description: f.Title + ": " + f.Message, CheckName: f.RuleID, Fingerprint: hex.EncodeToString(sum[:16]),
			Severity: sev, Location: location{Path: f.File, Lines: lines{Begin: max(f.Line, 1)}}})
	}
	return json.MarshalIndent(out, "", "  ")
}

// ciLevel maps severities to error, warning or notice for CI annotations.
func ciLevel(s Severity) string {
	switch s {
	case Critical, High:
		return "error"
	case Medium:
		return "warning"
	}
	return "notice"
}

// GitHubAnnotations renders workflow commands, so findings show on the pull
// request's files without code scanning or SARIF upload rights.
func GitHubAnnotations(r *Report) string {
	esc := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	prop := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	var b strings.Builder
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		fmt.Fprintf(&b, "::%s file=%s,line=%d,title=%s::%s\n", ciLevel(f.Severity), prop.Replace(f.File), max(f.Line, 1),
			prop.Replace(f.RuleID+" "+f.Title), esc.Replace(f.Message+" Fix: "+f.Remediation))
	}
	return b.String()
}

// AzureDevOps renders ##vso logging commands for Azure Pipelines.
func AzureDevOps(r *Report) string {
	prop := strings.NewReplacer(";", ",", "]", ")", "\r", " ", "\n", " ")
	var b strings.Builder
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		level := "warning"
		if ciLevel(f.Severity) == "error" {
			level = "error"
		}
		fmt.Fprintf(&b, "##vso[task.logissue type=%s;sourcepath=%s;linenumber=%d;code=%s]%s\n", level, prop.Replace(f.File), max(f.Line, 1), f.RuleID,
			strings.NewReplacer("\r", " ", "\n", " ").Replace(f.Title+": "+f.Message))
	}
	return b.String()
}

// Checkstyle renders the checkstyle XML format read by Jenkins, Bitbucket and many IDEs.
func Checkstyle(r *Report) ([]byte, error) {
	type issue struct {
		Line     int    `xml:"line,attr"`
		Severity string `xml:"severity,attr"`
		Message  string `xml:"message,attr"`
		Source   string `xml:"source,attr"`
	}
	type file struct {
		Name   string  `xml:"name,attr"`
		Errors []issue `xml:"error"`
	}
	byFile := map[string]*file{}
	var order []string
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		if byFile[f.File] == nil {
			byFile[f.File] = &file{Name: f.File}
			order = append(order, f.File)
		}
		sev := map[string]string{"error": "error", "warning": "warning", "notice": "info"}[ciLevel(f.Severity)]
		byFile[f.File].Errors = append(byFile[f.File].Errors, issue{Line: f.Line, Severity: sev, Message: f.Title + ": " + f.Message, Source: "terraguard." + f.RuleID})
	}
	doc := struct {
		XMLName xml.Name `xml:"checkstyle"`
		Version string   `xml:"version,attr"`
		Files   []file   `xml:"file"`
	}{Version: "4.3"}
	for _, n := range order {
		doc.Files = append(doc.Files, *byFile[n])
	}
	b, err := xml.MarshalIndent(doc, "", "  ")
	return append([]byte(xml.Header), b...), err
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

// coverageLine is the one-line summary of what was checked.
func coverageLine(c *Coverage) string {
	line := fmt.Sprintf("Checked %d resource(s) with %d rule evaluations: %d passed, %d failed.", c.Resources, c.Checks, c.Passed, c.Failed)
	if n := c.Resources - c.Covered; n > 0 {
		types := c.Uncovered
		if len(types) > 6 {
			types = append(append([]string{}, types[:6]...), fmt.Sprintf("and %d more", len(c.Uncovered)-6))
		}
		line += fmt.Sprintf(" %d resource(s) have no rule written for their type (%s).", n, strings.Join(types, ", "))
	}
	return line
}
