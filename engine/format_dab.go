package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Databricks Asset Bundles: databricks.yml and the resource files it
// includes. Bundle resources are the REST API create payloads in YAML, which
// the Terraform provider also mirrors, so jobs, pipelines, clusters and SQL
// warehouses become databricks_job, databricks_pipeline, databricks_cluster
// and databricks_sql_endpoint with the provider's block names (tasks -> task)
// and the Databricks rules apply unchanged. ${var.x} is resolved from the
// variable's default when no target sets a different value; every other
// substitution is decided at deploy time and stays unknown.

const FormatDAB = "databricks-bundle"

func init() { formatParsers[FormatDAB] = parseDAB }

// dabResourceKinds maps bundle resource kinds to Terraform types.
var dabResourceKinds = map[string]string{
	"jobs": "databricks_job", "pipelines": "databricks_pipeline", "clusters": "databricks_cluster", "sql_warehouses": "databricks_sql_endpoint",
}

// An included resource file has a top-level resources: whose first key is a bundle resource kind.
var dabResourcesRE = regexp.MustCompile(`(?m)^resources:[ \t]*(?:#.*)?\n(?:[ \t]*(?:#.*)?\n)*[ \t]+(?:jobs|pipelines|clusters|sql_warehouses|schemas|volumes|experiments|models|registered_models|model_serving_endpoints|quality_monitors|dashboards|apps|secret_scopes|database_instances|database_catalogs|synced_database_tables|alerts):[ \t]*(?:#.*)?$`)

// shortcut: included resource files are recognised by content (dabResourcesRE),
// not by following include: globs, since parsers see one file at a time; variables
// declared in databricks.yml therefore stay unknown in them.

// dabRenames are API list names whose Terraform block is singular.
var dabRenames = map[string]string{
	"tasks": "task", "job_clusters": "job_cluster", "clusters": "cluster", "libraries": "library",
	"environments": "environment", "parameters": "parameter", "notifications": "notification",
}

// dabMapAttrs are free-form maps, kept as maps (Terraform map attributes) rather than blocks.
var dabMapAttrs = map[string]bool{
	"spark_conf": true, "spark_env_vars": true, "custom_tags": true, "tags": true, "configuration": true,
	"base_parameters": true, "named_parameters": true, "extra_configs": true,
}

var dabVarRE = regexp.MustCompile(`\$\{var\.([A-Za-z0-9_-]+)\}`)

func parseDAB(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	var syntax []Finding
	if err != nil {
		syntax = append(syntax, formatSyntax(name, "Databricks bundle", err))
	}
	var out []*Resource
	for di, d := range docs {
		root, _ := d.value.(map[string]any)
		res, _ := root["resources"].(map[string]any)
		vars := dabVars(root)
		for _, kind := range sortedKeys(dabResourceKinds) {
			group, _ := res[kind].(map[string]any)
			for _, id := range sortedKeys(group) {
				obj, _ := group[id].(map[string]any)
				if obj == nil {
					continue
				}
				base := "resources." + kind + "." + id
				typ := dabResourceKinds[kind]
				r := &Resource{Address: typ + "." + id, Mode: "managed", Type: typ, Name: id, File: name, Line: d.lines[base],
					Lines: map[string]int{}, Via: map[string]string{}, Doc: di, Root: base}
				c := dabConv{vars: vars, lines: d.lines, out: r.Lines, via: r.Via}
				r.Attrs, _ = c.value(obj, base, "", 0, false).(map[string]any)
				// The top-level run_as applies to every job and pipeline that does not set its own.
				if ra, ok := root["run_as"].(map[string]any); ok && (kind == "jobs" || kind == "pipelines") && r.Attrs["run_as"] == nil {
					r.Attrs["run_as"] = c.value(ra, "run_as", "run_as", 0, false)
				}
				out = append(out, r)
			}
		}
	}
	return out, syntax
}

// dabVars returns the variables whose value is the same for every target.
func dabVars(root map[string]any) map[string]any {
	decl, _ := root["variables"].(map[string]any)
	targets, _ := root["targets"].(map[string]any)
	out := map[string]any{}
	for _, n := range sortedKeys(decl) {
		var vals []any
		switch d := decl[n].(type) {
		case map[string]any:
			if d["lookup"] != nil {
				continue // resolved by name in the workspace at deploy time
			}
			if v, ok := d["default"]; ok {
				vals = append(vals, v)
			}
		default:
			vals = append(vals, d)
		}
		for _, t := range sortedKeys(targets) {
			tm, _ := targets[t].(map[string]any)
			tv, _ := tm["variables"].(map[string]any)
			v, ok := tv[n]
			if !ok {
				continue
			}
			if m, isMap := v.(map[string]any); isMap && len(m) == 1 && m["default"] != nil {
				v = m["default"]
			}
			vals = append(vals, v)
		}
		if len(vals) == 0 {
			continue
		}
		same := true
		for _, v := range vals[1:] {
			same = same && fmt.Sprint(v) == fmt.Sprint(vals[0])
		}
		if same {
			out[n] = vals[0]
		}
	}
	return out
}

// dabConv converts bundle YAML into the provider's shape and records lines.
type dabConv struct {
	vars  map[string]any
	lines map[string]int // source lines, by YAML path
	out   map[string]int // lines by Terraform path
	via   map[string]string
}

// value converts v found at src (YAML path) to its Terraform form at dst. A
// map becomes a one-element block list unless asMap; depth bounds variables
// that refer to each other.
func (c dabConv) value(v any, src, dst string, depth int, block bool) any {
	if depth > 10 {
		return Unknown{Expr: fmt.Sprint(v)}
	}
	if l, ok := c.lines[src]; ok && dst != "" {
		k8sRecord(c.out, dst, l)
	}
	switch t := v.(type) {
	case string:
		if !strings.Contains(t, "${") {
			return t
		}
		if m := dabVarRE.FindStringSubmatch(t); m != nil && m[0] == t {
			if val, ok := c.vars[m[1]]; ok {
				c.via[dst] = "var." + m[1]
				return c.value(val, src, dst, depth+1, block)
			}
			return Unknown{Expr: t}
		}
		s, known := t, true
		s = dabVarRE.ReplaceAllStringFunc(s, func(ref string) string {
			val, ok := c.vars[dabVarRE.FindStringSubmatch(ref)[1]]
			switch val.(type) {
			case string, float64, bool:
				if ok {
					return fmt.Sprint(val)
				}
			}
			known = false
			return ref
		})
		if !known || strings.Contains(s, "${") {
			return Unknown{Expr: t}
		}
		c.via[dst] = "a bundle variable"
		return s
	case map[string]any:
		m := map[string]any{}
		inner := dst
		if block {
			inner = join(dst, "0")
			if dst != "" {
				k8sRecord(c.out, inner, c.lines[src])
			}
		}
		for _, k := range sortedKeys(t) {
			nk := k
			if r := dabRenames[k]; r != "" {
				nk = r
			}
			m[nk] = c.value(t[k], join(src, k), join(inner, nk), depth, !dabMapAttrs[k])
		}
		if block {
			return []any{m}
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, e := range t {
			ip, dp := src+"."+strconv.Itoa(i), dst+"."+strconv.Itoa(i)
			l[i] = c.value(e, ip, dp, depth, false) // a list element is already one block
		}
		return l
	}
	return v
}
