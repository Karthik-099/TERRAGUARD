package engine

import (
	"strconv"
	"strings"
	"sync"
)

// Azure Resource Manager templates: one Resource per entry in "resources"
// (nested children included, with their full type and parent/child name).
// Attrs hold the resource object, so paths start "properties.". Expressions
// resolve to literal parameter defaults and variables, otherwise Unknown.

func init() { formatParsers[FormatARM] = parseARM }

func parseARM(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(armStripComments(src))
	if err != nil {
		return nil, []Finding{formatSyntax(name, "ARM template", err)}
	}
	if len(docs) == 0 {
		return nil, nil
	}
	root, ok := docs[0].value.(map[string]any)
	if !ok {
		return nil, nil
	}
	p := &armParser{lines: docs[0].lines, params: armDefaults(root)}
	p.vars, _ = root["variables"].(map[string]any)
	ps, _ := root["parameters"].(map[string]any)
	p.walk(root["resources"], "resources", "", "")
	p.linkChildren()
	out := p.out
	// secure parameters are checked for hard-coded defaults
	for _, k := range sortedKeys(ps) {
		pm, _ := ps[k].(map[string]any)
		if t, _ := pm["type"].(string); strings.EqualFold(t, "secureString") || strings.EqualFold(t, "secureObject") {
			base := "parameters." + k
			out = append(out, &Resource{Address: "parameter." + k, Mode: "managed", Type: "parameter", Name: k,
				Line: p.lines[base], Lines: subLines(p.lines, base), Attrs: pm})
		}
	}
	return out, nil
}

// armDefaults maps each template parameter to its default value.
func armDefaults(tpl map[string]any) map[string]any {
	out := map[string]any{}
	ps, _ := tpl["parameters"].(map[string]any)
	for k, v := range ps {
		if pm, ok := v.(map[string]any); ok {
			if d, ok := pm["defaultValue"]; ok {
				out[k] = d
			}
		}
	}
	return out
}

type armParser struct {
	lines        map[string]int
	params, vars map[string]any
	out          []*Resource
	nested       map[*Resource]bool
}

// walk reads a resources list or symbolic-name object found at path.
func (p *armParser) walk(v any, path, parentType, parentName string) {
	var keys []string
	switch t := v.(type) {
	case []any:
		for i := range t {
			keys = append(keys, strconv.Itoa(i))
		}
	case map[string]any:
		keys = sortedKeys(t)
	default:
		return
	}
	for _, k := range keys {
		var obj map[string]any
		if l, ok := v.([]any); ok {
			i, _ := strconv.Atoi(k)
			obj, _ = l[i].(map[string]any)
		} else {
			obj, _ = v.(map[string]any)[k].(map[string]any)
		}
		typ, _ := p.resolve(obj["type"], 0).(string)
		typ = strings.TrimSuffix(typ, "/")
		if obj == nil || typ == "" {
			continue
		}
		name := armText(p.resolve(obj["name"], 0))
		if parentType != "" {
			if !strings.Contains(strings.SplitN(typ, "/", 2)[0], ".") { // a relative child type
				typ = parentType + "/" + typ
			}
			if strings.Count(name, "/") < strings.Count(typ, "/")-1 {
				name = parentName + "/" + name
			}
		}
		base := path + "." + k
		attrs, _ := p.resolve(obj, 0).(map[string]any)
		typ = armCanonicalType(typ)
		r := &Resource{Address: typ + "." + name, Mode: "managed", Type: typ, Name: name, Line: p.lines[base], Lines: subLines(p.lines, base), Attrs: attrs}
		p.out = append(p.out, r)
		if parentType != "" {
			if p.nested == nil {
				p.nested = map[*Resource]bool{}
			}
			p.nested[r] = true
		}
		p.walk(obj["resources"], base+".resources", typ, name)
		if strings.EqualFold(typ, "Microsoft.Resources/deployments") { // an inline nested template
			if tpl, ok := get(obj, "properties.template").(map[string]any); ok {
				q := p
				if strings.EqualFold(armText(get(obj, "properties.expressionEvaluationOptions.scope")), "inner") {
					q = &armParser{lines: p.lines, params: armDefaults(tpl), out: p.out, nested: p.nested}
					q.vars, _ = tpl["variables"].(map[string]any)
				}
				q.walk(tpl["resources"], base+".properties.template.resources", "", "")
				p.out, p.nested = q.out, q.nested
			}
		}
	}
}

// linkChildren lists top-level child resources under their parent's
// "resources", since ARM treats both forms the same.
func (p *armParser) linkChildren() {
	byKey := map[string]*Resource{}
	for _, r := range p.out {
		byKey[strings.ToLower(r.Type+"|"+r.Name)] = r
	}
	for _, r := range p.out {
		ti, ni := strings.LastIndex(r.Type, "/"), strings.LastIndex(r.Name, "/")
		if p.nested[r] || ni < 0 || strings.Count(r.Type, "/") < 2 {
			continue
		}
		parent := byKey[strings.ToLower(r.Type[:ti]+"|"+r.Name[:ni])]
		if parent == nil || parent.Attrs == nil {
			continue
		}
		child := map[string]any{}
		for k, v := range r.Attrs {
			child[k] = v
		}
		child["type"], child["name"] = r.Type, r.Name
		kids, _ := parent.Attrs["resources"].([]any)
		parent.Attrs["resources"] = append(kids, child)
	}
}

const armMaxDepth = 20

// resolve evaluates expressions in v; values it cannot work out become Unknown.
func (p *armParser) resolve(v any, depth int) any {
	switch t := v.(type) {
	case string:
		if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
			return t
		}
		if strings.HasPrefix(t, "[[") {
			return t[1:] // an escaped literal
		}
		if depth < armMaxDepth {
			e := &armExpr{s: t[1 : len(t)-1], p: p, depth: depth}
			if x, ok := e.value(); ok && e.done() {
				return x
			}
		}
		return Unknown{Expr: t}
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = p.resolve(x, depth)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = p.resolve(x, depth)
		}
		return out
	}
	return v
}

// armExpr evaluates the small part of the ARM expression language that
// yields literals: string, number and boolean constants, parameters(),
// variables(), concat(), toLower() and toUpper().
type armExpr struct {
	s     string
	i     int
	p     *armParser
	depth int
}

func (e *armExpr) skip() {
	for e.i < len(e.s) && e.s[e.i] == ' ' {
		e.i++
	}
}

func (e *armExpr) done() bool { e.skip(); return e.i == len(e.s) }

func (e *armExpr) value() (any, bool) {
	e.skip()
	if e.i >= len(e.s) {
		return nil, false
	}
	if e.s[e.i] == '\'' {
		var b strings.Builder
		for e.i++; e.i < len(e.s); e.i++ {
			if e.s[e.i] == '\'' {
				if e.i+1 < len(e.s) && e.s[e.i+1] == '\'' {
					b.WriteByte('\'')
					e.i++
					continue
				}
				e.i++
				return b.String(), true
			}
			b.WriteByte(e.s[e.i])
		}
		return nil, false
	}
	start := e.i
	for e.i < len(e.s) && (armWordByte(e.s[e.i]) || e.s[e.i] == '.' || e.s[e.i] == '-') {
		e.i++
	}
	word := e.s[start:e.i]
	if word == "" {
		return nil, false
	}
	e.skip()
	if e.i >= len(e.s) || e.s[e.i] != '(' {
		switch word {
		case "true", "false":
			return word == "true", true
		}
		f, err := strconv.ParseFloat(word, 64)
		return f, err == nil
	}
	e.i++
	var args []any
	for {
		e.skip()
		if e.i < len(e.s) && e.s[e.i] == ')' {
			e.i++
			break
		}
		a, ok := e.value()
		if !ok {
			return nil, false
		}
		args = append(args, a)
		e.skip()
		if e.i < len(e.s) && e.s[e.i] == ',' {
			e.i++
		}
	}
	if e.i < len(e.s) && (e.s[e.i] == '.' || e.s[e.i] == '[') {
		return nil, false // property or index access
	}
	one := func() (string, bool) {
		if len(args) != 1 {
			return "", false
		}
		s, ok := args[0].(string)
		return s, ok
	}
	switch strings.ToLower(word) {
	case "parameters", "variables":
		k, ok := one()
		src := e.p.params
		if strings.EqualFold(word, "variables") {
			src = e.p.vars
		}
		x, set := src[k]
		if !ok || !set {
			return nil, false
		}
		x = e.p.resolve(x, e.depth+1)
		return x, !isUnknown(x)
	case "concat":
		var b strings.Builder
		for _, a := range args {
			s, ok := a.(string)
			if !ok {
				return nil, false // arrays and numbers are left unresolved
			}
			b.WriteString(s)
		}
		return b.String(), true
	case "tolower", "toupper":
		s, ok := one()
		if strings.EqualFold(word, "tolower") {
			return strings.ToLower(s), ok
		}
		return strings.ToUpper(s), ok
	}
	return nil, false
}

func armWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// armText is a resolved name, or its expression when it cannot be resolved.
func armText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case Unknown:
		return t.Expr
	}
	return ""
}

// armTypes maps lower-cased ARM types used by rules to their spelling there,
// since ARM types are case-insensitive but rules match exactly. Exact
// spellings are kept under "=" so a type two rules spell differently stays.
var armTypes = sync.OnceValue(func() map[string]string {
	m := map[string]string{}
	for _, r := range Rules {
		for _, t := range r.Types {
			if strings.HasPrefix(t, "Microsoft.") {
				m["="+t] = t
				if _, ok := m[strings.ToLower(t)]; !ok {
					m[strings.ToLower(t)] = t
				}
			}
		}
	}
	return m
})

func armCanonicalType(t string) string {
	m := armTypes()
	if c, ok := m[strings.ToLower(t)]; ok && m["="+t] == "" {
		return c
	}
	return t
}

// armStripComments blanks // and /* */ comments outside strings, which ARM
// tooling accepts, keeping line numbers.
func armStripComments(src string) string {
	if !strings.Contains(src, "//") && !strings.Contains(src, "/*") {
		return src
	}
	b := []byte(src)
	inStr := false
	for i := 0; i < len(b); i++ {
		switch {
		case inStr:
			if b[i] == '\\' {
				i++
			} else if b[i] == '"' {
				inStr = false
			}
		case b[i] == '"':
			inStr = true
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			for ; i < len(b) && !(b[i] == '*' && i+1 < len(b) && b[i+1] == '/'); i++ {
				if b[i] != '\n' {
					b[i] = ' '
				}
			}
			if i+1 < len(b) {
				b[i], b[i+1] = ' ', ' '
				i++
			}
		}
	}
	return string(b)
}
