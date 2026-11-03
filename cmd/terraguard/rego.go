package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// regoFindings runs Conftest-style Rego policies: every package's deny,
// violation and warn rules. With a plan the input is the plan JSON, as
// `conftest test plan.json` uses; otherwise it is the parsed resources in
// the shape Conftest gives .tf files: {"resource": {type: {name: [body]}}}.
func regoFindings(dirs []string, files map[string]string, plan string) ([]engine.Finding, error) {
	modules := map[string]string{}
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasSuffix(p, ".rego") || strings.HasSuffix(p, "_test.rego") {
				return err
			}
			b, err := os.ReadFile(p)
			modules[p] = string(b)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	if len(modules) == 0 {
		return nil, nil
	}
	var input any
	if plan != "" {
		if err := json.Unmarshal([]byte(plan), &input); err != nil {
			return nil, fmt.Errorf("rego: plan is not valid JSON: %w", err)
		}
	} else {
		input = hclInput(files)
	}
	opts := []func(*rego.Rego){rego.Query("data"), rego.Input(input), rego.Capabilities(offlineCapabilities())}
	pkgs := map[string]bool{}
	for name, src := range modules {
		m, err := ast.ParseModule(name, src)
		if err != nil {
			return nil, fmt.Errorf("rego: %w", err)
		}
		pkgs[strings.TrimPrefix(m.Package.Path.String(), "data.")] = true
		opts = append(opts, rego.Module(name, src))
	}
	rs, err := rego.New(opts...).Eval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("rego: %w", err)
	}
	var out []engine.Finding
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	data, _ := rs[0].Expressions[0].Value.(map[string]any)
	names := make([]string, 0, len(pkgs))
	for p := range pkgs {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, pkg := range names {
		node := any(data)
		for _, seg := range strings.Split(pkg, ".") {
			m, _ := node.(map[string]any)
			node = m[seg]
		}
		rules, _ := node.(map[string]any)
		for _, rule := range []string{"deny", "violation", "warn"} {
			sev := engine.High
			if rule == "warn" {
				sev = engine.Low
			}
			for _, msg := range regoMessages(rules[rule]) {
				out = append(out, engine.Finding{RuleID: "OPA." + pkg + "." + rule, Severity: sev, Category: engine.CatPolicy,
					Title: "Rego policy " + pkg + " " + rule, Message: msg, File: "rego"})
			}
		}
	}
	return out, nil
}

// regoMessages accepts the set or list a rule produces: strings, or objects with msg.
func regoMessages(v any) []string {
	var out []string
	items, _ := v.([]any)
	for _, it := range items {
		switch t := it.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			if m, ok := t["msg"].(string); ok {
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func hclInput(files map[string]string) map[string]any {
	m := engine.Parse(files)
	res := map[string]any{}
	data := map[string]any{}
	for _, r := range m.Resources {
		target := res
		if r.Mode == "data" {
			target = data
		}
		byType, _ := target[r.Type].(map[string]any)
		if byType == nil {
			byType = map[string]any{}
			target[r.Type] = byType
		}
		byType[r.Name] = []any{plainValues(r.Attrs)}
	}
	return map[string]any{"resource": res, "data": data}
}

// plainValues turns unresolved expressions into their source text.
func plainValues(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = plainValues(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = plainValues(e)
		}
		return out
	case engine.Unknown:
		return "${" + t.Expr + "}"
	}
	return v
}

// offlineCapabilities removes the built-ins that reach the network or the
// host, so policies stay as offline as the rest of the scan.
func offlineCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	keep := caps.Builtins[:0]
	for _, b := range caps.Builtins {
		switch b.Name {
		case "http.send", "net.lookup_ip_addr", "opa.runtime", "net.cidr_expand":
			continue
		}
		keep = append(keep, b)
	}
	caps.Builtins = keep
	caps.AllowNet = []string{}
	return caps
}
