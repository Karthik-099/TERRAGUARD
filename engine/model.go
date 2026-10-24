// Package engine is TerraGuard's analysis core. It is pure Go with no I/O so
// the same code runs in the CLI, the GitHub Action, the MCP server and the
// browser (WebAssembly).
package engine

import (
	"sort"
	"strconv"
	"strings"
)

const Version = "2.0.0"

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

var severityRank = map[Severity]int{Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1}

// Rank orders severities; unknown values rank 0.
func (s Severity) Rank() int { return severityRank[s] }

func ParseSeverity(s string) Severity { return Severity(strings.ToUpper(strings.TrimSpace(s))) }

// Finding categories.
const (
	CatSecurity    = "security"
	CatValidate    = "validate"
	CatReliability = "reliability"
	CatBestPrac    = "best-practice"
	CatAttackPath  = "attack-path"
	CatPlan        = "plan"
	CatPolicy      = "policy"
	CatCost        = "cost"
)

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Message     string   `json:"message"`
	Resource    string   `json:"resource,omitempty"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Related     []string `json:"related,omitempty"`
	Fix         *Fix     `json:"fix,omitempty"`
	// Blocking means `terraform validate/plan/apply` is expected to fail.
	Blocking     bool   `json:"blocking,omitempty"`
	Waived       bool   `json:"waived,omitempty"`
	WaiverReason string `json:"waiver_reason,omitempty"`
}

// Fix is a machine-applicable edit: set attribute Path inside Block to Value.
type Fix struct {
	File        string   `json:"file"`
	Block       string   `json:"block"` // e.g. resource.aws_s3_bucket.logs, variable.db_password
	Path        []string `json:"path"`  // nested block names then attribute name
	Value       any      `json:"value"`
	Description string   `json:"description"`
}

// Unknown marks an attribute whose value is not a literal (references, function calls).
type Unknown struct{ Expr string }

// Resource is the normalized form shared by HCL sources and plan JSON, so every
// rule runs unchanged against both.
type Resource struct {
	Address  string
	Mode     string // "managed" or "data"
	Type     string
	Name     string
	File     string
	Line     int
	Attrs    map[string]any
	Lines    map[string]int // dotted attr path (with block indexes) -> line
	Refs     []string       // addresses this resource references
	FromPlan bool
}

func (r *Resource) line(path string) int {
	if l, ok := r.Lines[path]; ok {
		return l
	}
	return r.Line
}

// get walks a dotted path. Nested blocks are lists; a numeric segment indexes
// them, otherwise the first element is used.
func get(v any, path string) any {
	if path == "" {
		return v
	}
	for _, seg := range strings.Split(path, ".") {
		if l, ok := v.([]any); ok {
			if i, err := strconv.Atoi(seg); err == nil {
				if i >= len(l) {
					return nil
				}
				v = l[i]
				continue
			}
			if len(l) == 0 {
				return nil
			}
			v = l[0]
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[seg]
	}
	return v
}

func (r *Resource) get(path string) any { return get(r.Attrs, path) }

// blocks returns nested blocks (or a single object, as plan JSON sometimes has) at path.
func (r *Resource) blocks(name string) []map[string]any {
	var out []map[string]any
	switch v := r.Attrs[name].(type) {
	case []any:
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
	case map[string]any:
		out = append(out, v)
	}
	return out
}

func isUnknown(v any) bool { _, ok := v.(Unknown); return ok }

func asString(v any) (string, bool) { s, ok := v.(string); return s, ok }

func asBool(v any) (b, known bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string: // plan JSON / tfvars sometimes carry "true"
		if t == "true" || t == "false" {
			return t == "true", true
		}
	}
	return false, false
}

func asFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	return 0, false
}

// strings returns the known string elements of a string or list value.
func asStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Waived != b.Waived {
			return !a.Waived
		}
		if a.Blocking != b.Blocking {
			return a.Blocking
		}
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}
