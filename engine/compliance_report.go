package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// ComplianceSchema versions the JSON of ComplianceDoc; bump it on any breaking change.
const ComplianceSchema = "terraguard.compliance/v1"

// ComplianceDisclaimer is printed at the top of every compliance report.
const ComplianceDisclaimer = "Automated evidence from static analysis of infrastructure code. This is not a certification, an audit opinion or proof of compliance; an assessor must review it together with evidence from the running environment, processes and people."

// ComplianceKeys are the --framework values, in display order.
var ComplianceKeys = []string{"soc2", "iso27001", "cis", "pci", "hipaa"}

var complianceKeyName = map[string]string{
	"soc2": "SOC 2 (TSC 2017)", "iso27001": "ISO/IEC 27001:2022", "cis": "CIS Controls v8",
	"pci": "PCI DSS v4.0", "hipaa": "HIPAA Security Rule",
}

// ComplianceDoc is an audit-ready report for one framework.
type ComplianceDoc struct {
	Schema       string `json:"schema"`
	Framework    string `json:"framework"`
	FrameworkKey string `json:"framework_key"`
	GeneratedAt  string `json:"generated_at"`
	Version      string `json:"terraguard_version"`
	RulesVersion string `json:"rules_version"`
	// FilesSHA256 is FilesDigest of the scanned files; the caller sets it.
	FilesSHA256 string              `json:"files_sha256"`
	FileCount   int                 `json:"file_count"`
	Disclaimer  string              `json:"disclaimer"`
	MappingNote []string            `json:"mapping_notes"`
	Summary     ComplianceSummary   `json:"summary"`
	Controls    []ComplianceControl `json:"controls"`
}

type ComplianceSummary struct {
	Pass        int `json:"pass"`
	Fail        int `json:"fail"`
	NotAssessed int `json:"not_assessed"`
}

// ComplianceControl is one framework control and the checks behind it.
type ComplianceControl struct {
	ID     string   `json:"id"`
	Themes []string `json:"themes"`
	// Status is pass, fail or not_assessed.
	Status string `json:"status"`
	// RulesMapped counts rules mapped to the control; RulesApplied are those
	// that judged at least one scanned resource or reported a finding.
	RulesMapped  int                 `json:"rules_mapped"`
	RulesApplied []string            `json:"rules_applied"`
	Failures     []ComplianceFailure `json:"failures"`
	Waivers      []ComplianceWaiver  `json:"waivers"`
}

type ComplianceFailure struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Resource string   `json:"resource,omitempty"`
	File     string   `json:"file,omitempty"`
	Line     int      `json:"line,omitempty"`
	Message  string   `json:"message"`
}

// ComplianceWaiver is a waiver that matched a finding of the control. An
// expired waiver no longer covers its finding, which then appears in Failures.
type ComplianceWaiver struct {
	RuleID     string `json:"rule_id"`
	Resource   string `json:"resource,omitempty"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Expires    string `json:"expires,omitempty"`
	Expired    bool   `json:"expired"`
}

// FilesDigest is sha256 over the files sorted by path, each written as
// "<len(path)>:<path><len(content)>:<content>" so no two file sets collide.
func FilesDigest(files map[string]string) string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s%d:%s", len(k), k, len(files[k]), files[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ComplianceReport groups the report's checks by the framework's controls,
// using the existing theme mapping. rep should come from a scan with
// Input.Coverage set, so rules that ran without a finding count as applied.
// cfg (may be nil) supplies waiver details; now decides waiver expiry.
func ComplianceReport(rep *Report, cfg *Config, framework string, now time.Time) (*ComplianceDoc, error) {
	key := strings.ToLower(strings.TrimSpace(framework))
	name, ok := complianceKeyName[key]
	if !ok {
		return nil, fmt.Errorf("unknown framework %q (want one of %s)", framework, strings.Join(ComplianceKeys, ", "))
	}
	var controls map[string]string
	for _, fw := range frameworks {
		if fw.name == name {
			controls = fw.controls
		}
	}
	if cfg == nil {
		cfg = &Config{}
	}
	doc := &ComplianceDoc{Schema: ComplianceSchema, Framework: name, FrameworkKey: key, GeneratedAt: now.UTC().Format(time.RFC3339),
		Version: Version, RulesVersion: RulesVersion, Disclaimer: ComplianceDisclaimer, FileCount: rep.Stats.Files}
	doc.MappingNote = []string{
		"The mapping is coarse: TerraGuard maps each rule to one or more of 8 control themes, and each theme to a single control of the framework. A pass means no mapped check failed, not that the control is met.",
		"Controls not listed are not assessed by TerraGuard at all. Rules without an explicit theme are mapped by their CWE.",
	}
	var missing []string
	for t := range themeTitles {
		if _, ok := controls[t]; !ok {
			missing = append(missing, themeTitles[t])
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		doc.MappingNote = append(doc.MappingNote, "This framework has no mapped control for: "+strings.Join(missing, ", ")+".")
	}

	// Group themes by control ID: several themes can share one control.
	byControl := map[string][]string{}
	for t, id := range controls {
		byControl[id] = append(byControl[id], t)
	}
	types := map[string]bool{}
	if rep.Coverage != nil {
		for _, it := range rep.Coverage.Items {
			types[it.Type] = true
		}
	}
	fired := map[string]bool{}
	for _, f := range rep.Findings {
		fired[f.RuleID] = true
	}
	ids := make([]string, 0, len(byControl))
	for id := range byControl {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		themes := byControl[id]
		sort.Strings(themes)
		c := ComplianceControl{ID: id, RulesApplied: []string{}, Failures: []ComplianceFailure{}, Waivers: []ComplianceWaiver{}}
		inTheme := func(rule string) bool {
			for _, t := range themesOf(rule) {
				for _, want := range themes {
					if t == want {
						return true
					}
				}
			}
			return false
		}
		for _, t := range themes {
			c.Themes = append(c.Themes, themeTitles[t])
		}
		for rid, r := range ruleIndex {
			if !inTheme(rid) {
				continue
			}
			c.RulesMapped++
			// A rule without resource types (module, plan, secret checks) counts only when it fired,
			// so a plan-only rule never makes a control look assessed without a plan.
			ran := fired[rid]
			for t := range types {
				ran = ran || (len(r.Types) > 0 && r.applies(t))
			}
			if ran {
				c.RulesApplied = append(c.RulesApplied, rid)
			}
		}
		sort.Strings(c.RulesApplied)
		for _, f := range rep.Findings {
			if !inTheme(f.RuleID) {
				continue
			}
			if !f.Waived {
				c.Failures = append(c.Failures, ComplianceFailure{RuleID: f.RuleID, Severity: f.Severity, Title: f.Title, Resource: f.Resource, File: f.File, Line: f.Line, Message: f.Message})
			}
			matched := false
			for _, w := range cfg.Waivers {
				if ok, _ := path.Match(w.Rule, f.RuleID); !ok {
					continue
				}
				if w.Resource != "" {
					if ok, _ := path.Match(w.Resource, f.Resource); !ok {
						continue
					}
				}
				expired := false
				if w.Expires != "" {
					exp, err := time.Parse("2006-01-02", w.Expires)
					expired = err != nil || now.After(exp.Add(24*time.Hour)) // same rule as the policy engine
				}
				if expired == f.Waived {
					continue // a waived finding's cover is a live waiver; an active one shows only expired waivers
				}
				c.Waivers = append(c.Waivers, ComplianceWaiver{RuleID: f.RuleID, Resource: f.Resource, File: f.File, Line: f.Line,
					Reason: w.Reason, ApprovedBy: w.ApprovedBy, Expires: w.Expires, Expired: expired})
				matched = true
				break
			}
			if f.Waived && !matched { // inline ignore, baseline or rules_version pin
				c.Waivers = append(c.Waivers, ComplianceWaiver{RuleID: f.RuleID, Resource: f.Resource, File: f.File, Line: f.Line, Reason: f.WaiverReason})
			}
		}
		switch {
		case len(c.Failures) > 0:
			c.Status = "fail"
			doc.Summary.Fail++
		case len(c.RulesApplied) > 0:
			c.Status = "pass"
			doc.Summary.Pass++
		default:
			c.Status = "not_assessed"
			doc.Summary.NotAssessed++
		}
		doc.Controls = append(doc.Controls, c)
	}
	return doc, nil
}
