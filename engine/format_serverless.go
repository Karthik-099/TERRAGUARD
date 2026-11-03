package engine

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Serverless Framework files: resources.Resources is read as CloudFormation,
// plus one serverless_function per function (with the provider defaults it
// inherits) and one serverless_provider.

func init() { formatParsers[FormatServerless] = parseServerless }

var slsVarRE = regexp.MustCompile(`\$\{([^{}]+)\}`)

func parseServerless(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	if err != nil {
		return nil, []Finding{formatSyntax(name, "Serverless", err)}
	}
	if len(docs) == 0 {
		return nil, nil
	}
	root, ok := docs[0].value.(map[string]any)
	if !ok {
		return nil, nil
	}
	lines := docs[0].lines
	root, _ = slsResolve(root, root, 0).(map[string]any)

	var out []*Resource
	switch rs := root["resources"].(type) {
	case map[string]any:
		out = append(out, cfnResources(rs, lines, "resources.")...)
	case []any: // a list of inline templates and ${file(...)} includes
		for i, e := range rs {
			if m, ok := e.(map[string]any); ok {
				out = append(out, cfnResources(m, lines, "resources."+strconv.Itoa(i)+".")...)
			}
		}
	}

	provider, _ := root["provider"].(map[string]any)
	if provider != nil {
		out = append(out, &Resource{Address: "serverless_provider.provider", Mode: "managed", Type: "serverless_provider", Name: "provider",
			Line: lines["provider"], Attrs: provider, Lines: subLines(lines, "provider")})
	}
	fns, _ := root["functions"].(map[string]any)
	names := make([]string, 0, len(fns))
	for n := range fns {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fn, _ := fns[n].(map[string]any)
		attrs := map[string]any{}
		for k, v := range fn {
			attrs[k] = v
		}
		fl := subLines(lines, "functions."+n)
		for k, v := range provider {
			if _, set := attrs[k]; !set && k != "iamRoleStatements" && k != "iam" {
				attrs[k] = v
				slsCopyLines(fl, lines, "provider."+k, k)
			}
		}
		// function variables override the provider's
		if pe, ok := provider["environment"].(map[string]any); ok {
			env := map[string]any{}
			for k, v := range pe {
				env[k] = v
			}
			fe, _ := fn["environment"].(map[string]any)
			for k, v := range fe {
				env[k] = v
			}
			for k := range pe {
				if _, own := fe[k]; !own {
					slsCopyLines(fl, lines, "provider.environment."+k, "environment."+k)
				}
			}
			attrs["environment"] = env
		}
		// the shared role's statements apply to every function
		stmts, _ := fn["iamRoleStatements"].([]any)
		stmts = append([]any(nil), stmts...)
		for _, src := range []string{"provider.iamRoleStatements", "provider.iam.role.statements"} {
			l, _ := get(root, src).([]any)
			for i, s := range l {
				slsCopyLines(fl, lines, src+"."+strconv.Itoa(i), "iamRoleStatements."+strconv.Itoa(len(stmts)))
				stmts = append(stmts, s)
			}
		}
		if len(stmts) > 0 {
			attrs["iamRoleStatements"] = stmts
		}
		out = append(out, &Resource{Address: "serverless_function." + n, Mode: "managed", Type: "serverless_function", Name: n,
			Line: lines["functions."+n], Attrs: attrs, Lines: fl})
	}
	return out, nil
}

// slsCopyLines copies the lines under from into dst, renamed to to.
func slsCopyLines(dst, lines map[string]int, from, to string) {
	for p, l := range lines {
		if p == from {
			dst[to] = l
		} else if rest, ok := strings.CutPrefix(p, from+"."); ok {
			dst[to+"."+rest] = l
		}
	}
}

// slsResolve substitutes ${self:...} references; other variables (env, opt,
// file, ssm) are decided at deploy time and become Unknown.
func slsResolve(v any, root map[string]any, depth int) any {
	if depth > 8 {
		return v
	}
	switch t := v.(type) {
	case string:
		if m := slsVarRE.FindStringSubmatch(t); m != nil && m[0] == t {
			if x, ok := slsLookup(m[1], root); ok {
				return slsResolve(x, root, depth+1)
			}
			return Unknown{Expr: t}
		}
		return slsVarRE.ReplaceAllStringFunc(t, func(s string) string {
			if x, ok := slsLookup(s[2:len(s)-1], root); ok {
				if str, ok := x.(string); ok && !strings.Contains(str, "${") {
					return str
				}
			}
			return s
		})
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = slsResolve(x, root, depth)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = slsResolve(x, root, depth)
		}
		return out
	}
	return v
}

func slsLookup(expr string, root map[string]any) (any, bool) {
	ref := strings.TrimSpace(strings.SplitN(expr, ",", 2)[0])
	p, ok := strings.CutPrefix(ref, "self:")
	if !ok || p == "" {
		return nil, false
	}
	x := get(root, p)
	return x, x != nil
}
