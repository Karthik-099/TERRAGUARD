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
	for _, f := range r.Findings {
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
			"message": obj{"text": f.Message}, "locations": []obj{loc}}
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
func Markdown(r *Report) string {
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
	fmt.Fprintf(&b, "| Critical | High | Medium | Low | Info | Waived | Auto-fixable |\n|---|---|---|---|---|---|---|\n| %d | %d | %d | %d | %d | %d | %d |\n\n",
		r.Summary[Critical], r.Summary[High], r.Summary[Medium], r.Summary[Low], r.Summary[Info], r.Waived, r.Fixable)
	if p := r.Plan; p != nil {
		fmt.Fprintf(&b, "**Plan:** %d to add, %d to change, %d to destroy, %d to replace.\n\n", p.Create, p.Update, p.Delete, p.Replace)
	}
	var active []Finding
	for _, f := range r.Findings {
		if !f.Waived {
			active = append(active, f)
		}
	}
	if len(active) == 0 {
		b.WriteString("No active findings.\n")
	} else {
		b.WriteString("| Severity | Rule | Location | Finding |\n|---|---|---|---|\n")
		for i, f := range active {
			if i == 50 {
				fmt.Fprintf(&b, "\n…and %d more. See the SARIF results in the Security tab.\n", len(active)-50)
				break
			}
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(&b, "| %s | `%s` | `%s` | **%s**: %s |\n", f.Severity, f.RuleID, loc, f.Title, strings.ReplaceAll(f.Message, "|", "\\|"))
		}
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
func Text(r *Report) string {
	var b strings.Builder
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		block := ""
		if f.Blocking {
			block = " [blocks apply]"
		}
		fmt.Fprintf(&b, "%-8s %-15s %s%s\n         %s\n         %s\n", f.Severity, f.RuleID, loc, block, f.Title+": "+f.Message, "fix: "+f.Remediation)
	}
	fmt.Fprintf(&b, "\n%s\nScore %d/100 (%s) · %d critical · %d high · %d medium · %d low · %d info · %d waived · %d auto-fixable\n",
		r.Verdict.Message, r.Score, r.Grade, r.Summary[Critical], r.Summary[High], r.Summary[Medium], r.Summary[Low], r.Summary[Info], r.Waived, r.Fixable)
	for _, g := range r.GateFailures {
		fmt.Fprintf(&b, "gate: %s\n", g)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "warning: %s\n", e)
	}
	return b.String()
}

// JUnit renders one test case per active finding, for CI systems that only
// understand JUnit XML (GitLab, Jenkins, Azure DevOps, CircleCI).
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

// CodeQuality renders the GitLab Code Quality report format, shown in merge
// request widgets and diffs.
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
