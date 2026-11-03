package engine

import (
	"encoding/json"
	"sort"
	"strings"
)

// CloudFormation (and SAM) templates: one Resource per entry in Resources,
// with Attrs holding the whole resource object, so paths start "Properties.".

func init() { formatParsers[FormatCloudFormation] = parseCloudFormation }

func parseCloudFormation(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	var syntax []Finding
	if err != nil {
		syntax = append(syntax, formatSyntax(name, "CloudFormation", err))
	}
	var out []*Resource
	for _, d := range docs {
		if root, ok := yaml11Bools(d.value).(map[string]any); ok {
			out = append(out, cfnResources(root, d.lines, "")...)
		}
	}
	return out, syntax
}

// cfnResources reads the Resources section of a template found at prefix in the file.
func cfnResources(root map[string]any, lines map[string]int, prefix string) []*Resource {
	res, _ := root["Resources"].(map[string]any)
	params := map[string]any{}
	if ps, ok := root["Parameters"].(map[string]any); ok {
		for k, p := range ps {
			pm, _ := p.(map[string]any)
			if d, ok := pm["Default"]; ok && !isUnknown(d) {
				params[k] = d
			}
		}
	}
	globals, _ := root["Globals"].(map[string]any)
	ids := make([]string, 0, len(res))
	for id := range res {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []*Resource
	for _, id := range ids {
		obj, ok := res[id].(map[string]any)
		typ, _ := obj["Type"].(string)
		if !ok || typ == "" {
			continue
		}
		base := prefix + "Resources." + id
		rl := subLines(lines, base)
		if kind, ok := strings.CutPrefix(typ, "AWS::Serverless::"); ok {
			if g, ok := globals[kind].(map[string]any); ok {
				obj = cfnApplyGlobals(obj, g, rl, subLines(lines, prefix+"Globals."+kind))
			}
		}
		r := &Resource{Address: typ + "." + id, Mode: "managed", Type: typ, Name: id, Line: lines[base], Lines: rl}
		seen := map[string]bool{}
		r.Attrs, _ = cfnResolve(obj, params, func(ref string) {
			o, _ := res[ref].(map[string]any)
			if t, ok := o["Type"].(string); ok && ref != id && !seen[ref] {
				seen[ref] = true
				r.Refs = append(r.Refs, t+"."+ref)
			}
		}).(map[string]any)
		out = append(out, r)
	}
	return out
}

// cfnApplyGlobals fills SAM Globals into Properties the resource does not set.
func cfnApplyGlobals(obj, g map[string]any, rl, gl map[string]int) map[string]any {
	props, _ := obj["Properties"].(map[string]any)
	merged := map[string]any{}
	for k, v := range props {
		merged[k] = v
	}
	for k, v := range g {
		if _, set := merged[k]; set {
			continue
		}
		merged[k] = v
		for p, l := range gl {
			if p == k || strings.HasPrefix(p, k+".") {
				rl["Properties."+p] = l
			}
		}
	}
	out := map[string]any{}
	for k, v := range obj {
		out[k] = v
	}
	out["Properties"] = merged
	return out
}

// cfnResolve turns intrinsic functions into Unknown values, resolving Ref to a
// parameter's Default when it has one; ref is called for each referenced logical ID.
func cfnResolve(v any, params map[string]any, ref func(string)) any {
	switch t := v.(type) {
	case Unknown:
		if name, ok := strings.CutPrefix(t.Expr, "!Ref "); ok {
			return cfnRef(strings.TrimSpace(name), t, params, ref)
		}
		if target, ok := strings.CutPrefix(t.Expr, "!GetAtt "); ok {
			ref(strings.Split(strings.TrimSpace(target), ".")[0])
		}
		return t
	case map[string]any:
		if len(t) == 1 {
			for k, x := range t {
				if k == "Ref" {
					if s, ok := x.(string); ok {
						return cfnRef(s, Unknown{Expr: "!Ref " + s}, params, ref)
					}
				}
				if strings.HasPrefix(k, "Fn::") {
					if k == "Fn::GetAtt" {
						switch a := x.(type) {
						case string:
							ref(strings.Split(a, ".")[0])
						case []any:
							if s, ok := cfnFirst(a); ok {
								ref(s)
							}
						}
					}
					b, _ := json.Marshal(cfnPlain(x))
					return Unknown{Expr: "!" + strings.TrimPrefix(k, "Fn::") + " " + string(b)}
				}
			}
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = cfnResolve(x, params, ref)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = cfnResolve(x, params, ref)
		}
		return out
	}
	return v
}

func cfnRef(name string, u Unknown, params map[string]any, ref func(string)) any {
	if name == "AWS::NoValue" {
		return nil
	}
	if d, ok := params[name]; ok {
		return d
	}
	ref(name)
	return u
}

func cfnFirst(l []any) (string, bool) {
	if len(l) == 0 {
		return "", false
	}
	s, ok := l[0].(string)
	return s, ok
}

// cfnPlain makes a value JSON-encodable (Unknown becomes its expression).
func cfnPlain(v any) any {
	switch t := v.(type) {
	case Unknown:
		return t.Expr
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = cfnPlain(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = cfnPlain(x)
		}
		return out
	}
	return v
}

// yaml11Bools reads YAML 1.1 booleans (Yes, No, On, Off), which CloudFormation accepts.
func yaml11Bools(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = yaml11Bools(e)
		}
	case []any:
		for i, e := range t {
			t[i] = yaml11Bools(e)
		}
	case string:
		switch t {
		case "Yes", "yes", "YES", "On", "on", "ON":
			return true
		case "No", "no", "NO", "Off", "off", "OFF":
			return false
		}
	}
	return v
}
