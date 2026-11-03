package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Graph policies use the common YAML policy format (attribute conditions,
// connections between resources that reference each other, and filters,
// combined with and/or/not), so existing custom policies run unchanged;
// users can load their own (terraguard scan --policy-dir).

// GCond is one condition of a graph policy.
type GCond struct {
	Kind      string   `json:"k"` // and, or, not, attribute, connection, filter, resource
	Sub       []GCond  `json:"s,omitempty"`
	Types     []string `json:"t,omitempty"` // resource_types; "all" matches every type
	Connected []string `json:"c,omitempty"`
	Attr      string   `json:"a,omitempty"`
	Op        string   `json:"o,omitempty"`
	Value     any      `json:"v,omitempty"`
	JSONPath  bool     `json:"j,omitempty"` // every match must satisfy the operator
}

// GraphPolicy is one parsed policy.
type GraphPolicy struct {
	ID, Title, Category string
	Severity            Severity
	Why                 string // finding message; built-in policies only
	Def                 GCond
}

// ParseGraphPolicy reads one policy in Checkov's YAML format.
func ParseGraphPolicy(src string) (*GraphPolicy, error) {
	var raw struct {
		Metadata struct {
			ID, Name, Category, Severity string
		} `yaml:"metadata"`
		Definition any `yaml:"definition"`
	}
	if err := yaml.Unmarshal([]byte(src), &raw); err != nil {
		return nil, fmt.Errorf("graph policy: %w", err)
	}
	if raw.Metadata.ID == "" || raw.Definition == nil {
		return nil, fmt.Errorf("graph policy: metadata.id and definition are required")
	}
	def, err := parseGCond(raw.Definition)
	if err != nil {
		return nil, fmt.Errorf("graph policy %s: %w", raw.Metadata.ID, err)
	}
	sev := ParseSeverity(raw.Metadata.Severity)
	if severityRank[sev] == 0 {
		sev = Medium
	}
	return &GraphPolicy{ID: raw.Metadata.ID, Title: raw.Metadata.Name, Category: raw.Metadata.Category, Severity: sev, Def: def}, nil
}

func parseGCond(v any) (GCond, error) {
	if l, ok := v.([]any); ok { // a bare list means and
		v = map[string]any{"and": l}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return GCond{}, fmt.Errorf("condition must be a map")
	}
	for _, op := range []string{"and", "or", "not"} {
		subs, ok := m[op]
		if !ok {
			continue
		}
		if one, isMap := subs.(map[string]any); isMap {
			subs = []any{one}
		}
		list, _ := subs.([]any)
		c := GCond{Kind: op}
		for _, s := range list {
			sc, err := parseGCond(s)
			if err != nil {
				return GCond{}, err
			}
			c.Sub = append(c.Sub, sc)
		}
		if len(c.Sub) == 0 || op == "not" && len(c.Sub) != 1 {
			return GCond{}, fmt.Errorf("%s needs conditions", op)
		}
		return c, nil
	}
	c := GCond{Attr: fmt.Sprint(orEmpty(m["attribute"])), Op: strings.TrimSpace(fmt.Sprint(orEmpty(m["operator"]))), Value: m["value"]}
	c.Types = strList(m["resource_types"])
	c.Connected = strList(m["connected_resource_types"])
	switch kind := fmt.Sprint(orEmpty(m["cond_type"])); kind {
	case "attribute", "connection", "filter", "resource":
		c.Kind = kind
	default:
		return GCond{}, fmt.Errorf("unsupported cond_type %q", kind)
	}
	if c.Kind == "attribute" && !graphOps[strings.TrimPrefix(c.Op, "jsonpath_")] {
		return GCond{}, fmt.Errorf("unsupported operator %q", c.Op)
	}
	if strings.HasPrefix(c.Op, "jsonpath_") {
		c.Op, c.JSONPath = strings.TrimPrefix(c.Op, "jsonpath_"), true
		c.Attr = jsonpathToPath(c.Attr)
	}
	if c.Kind == "filter" {
		c.Types = strList(c.Value)
	}
	if len(c.Types) == 0 {
		c.Types = []string{"all"}
	}
	return c, nil
}

func orEmpty(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func strList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

// jsonpathToPath turns the JSONPath forms the policies use into dotted
// segments: a[*] -> a.*, a[0] -> a.0, a[?(@.k == v)] -> a.?(@.k == v).
func jsonpathToPath(p string) string {
	p = strings.TrimPrefix(strings.TrimPrefix(p, "$"), ".")
	var segs []string
	for p != "" {
		switch {
		case p[0] == '.':
			p = p[1:]
		case p[0] == '[':
			end := strings.IndexByte(p, ']')
			if end < 0 {
				end = len(p) - 1
			}
			segs = append(segs, strings.Trim(p[1:end], "'\""))
			p = p[end+1:]
		default:
			end := strings.IndexAny(p, ".[")
			if end < 0 {
				end = len(p)
			}
			segs = append(segs, p[:end])
			p = p[end:]
		}
	}
	return strings.Join(segs, "\x00")
}

// pathSegs splits an attribute path; JSONPath ones are already split.
func pathSegs(p string) []string {
	if strings.Contains(p, "\x00") {
		return strings.Split(p, "\x00")
	}
	return strings.Split(p, ".")
}

var jpCondRE = regexp.MustCompile(`@\.([\w.]+)\s*(==|!=)\s*['"]?([^'"&|)]*?)['"]?\s*(?:[&|]|$)`)

// jpFilter keeps the elements that match a ?(@.k == v & ...) filter.
func jpFilter(seg string, elems []any) []any {
	expr := strings.TrimSuffix(strings.TrimPrefix(seg, "?("), ")")
	or := strings.Contains(expr, "|")
	conds := jpCondRE.FindAllStringSubmatch(expr+" ", -1)
	var out []any
	for _, e := range elems {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		hits := 0
		for _, c := range conds {
			eq := pyStr(get(m, c[1])) == strings.TrimSpace(c[3])
			if eq == (c[2] == "==") {
				hits++
			}
		}
		if len(conds) > 0 && (or && hits > 0 || !or && hits == len(conds)) {
			out = append(out, e)
		}
	}
	return out
}

var graphOps = map[string]bool{
	"equals": true, "not_equals": true, "equals_ignore_case": true, "not_equals_ignore_case": true,
	"exists": true, "not_exists": true, "any": true, "within": true, "not_within": true,
	"contains": true, "not_contains": true, "starting_with": true, "not_starting_with": true,
	"ending_with": true, "not_ending_with": true, "regex_match": true, "not_regex_match": true,
	"greater_than": true, "greater_than_or_equal": true, "less_than": true, "less_than_or_equal": true,
	"is_true": true, "is_false": true, "is_empty": true, "is_not_empty": true,
	"length_equals": true, "length_not_equals": true, "length_greater_than": true, "length_greater_than_or_equal": true,
	"length_less_than": true, "length_less_than_or_equal": true, "subset": true, "not_subset": true,
	"intersects": true, "not_intersects": true,
}

// tri-state results
const (
	gFail    = 0
	gPass    = 1
	gUnknown = -1
)

type gGraph struct {
	res   []*Resource
	byKey map[string]*Resource
	edges map[*Resource][]*Resource // both directions
}

func newGGraph(rs []*Resource) *gGraph {
	g := &gGraph{res: rs, byKey: map[string]*Resource{}, edges: map[*Resource][]*Resource{}}
	for _, r := range rs {
		g.byKey[gStrip(r.Address)] = r
	}
	link := func(a, b *Resource) {
		g.edges[a] = append(g.edges[a], b)
		g.edges[b] = append(g.edges[b], a)
	}
	byName := map[string][]*Resource{}
	for _, r := range rs {
		for _, ref := range r.Refs {
			if t := g.byKey[gStrip(ref)]; t != nil && t != r {
				link(r, t)
			}
		}
		// Resources that take the same name from one variable or local refer
		// to the same thing (a bucket and its versioning block).
		for _, attr := range nameAttrs {
			src := r.Via[attr]
			if u, ok := r.Attrs[attr].(Unknown); ok && src == "" && varOrLocalRE.MatchString(u.Expr) {
				src = u.Expr
			}
			if src != "" {
				byName[src] = append(byName[src], r)
			}
		}
	}
	for _, group := range byName {
		for i := 1; i < len(group); i++ {
			for _, o := range group[:i] {
				if o.Type != group[i].Type {
					link(group[i], o)
				}
			}
		}
	}
	return g
}

var (
	nameAttrs    = []string{"bucket", "function_name", "cluster_name", "cluster_identifier", "repository", "role"}
	varOrLocalRE = regexp.MustCompile(`^(var|local)\.[\w-]+$`)
)

var gKeysRE = regexp.MustCompile(`\[[^\]]*\]`)

func gStrip(addr string) string { return gKeysRE.ReplaceAllString(addr, "") }

func typeMatch(r *Resource, types []string) bool {
	for _, t := range types {
		if t == "all" || t == r.Type || r.Mode == "data" && t == "data."+r.Type {
			return true
		}
	}
	return false
}

func (c GCond) hasConnection() bool {
	for _, s := range c.Sub {
		if s.Kind == "connection" || (s.Kind == "and" || s.Kind == "or") && s.hasConnection() {
			return true
		}
	}
	return false
}

func (c GCond) allTypes() []string {
	if c.Kind != "and" && c.Kind != "or" && c.Kind != "not" {
		return c.Types
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range c.Sub {
		for _, t := range s.allTypes() {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

type gResult struct{ pass, fail, unknown map[*Resource]bool }

func newGResult() gResult {
	return gResult{map[*Resource]bool{}, map[*Resource]bool{}, map[*Resource]bool{}}
}

// solve returns the resources the condition passes, fails and cannot decide.
func (g *gGraph) solve(c GCond) gResult {
	switch {
	case c.Kind == "connection":
		return g.connection(c, nil, nil)
	case (c.Kind == "and" || c.Kind == "or") && c.hasConnection():
		return g.complexConnection(c)
	}
	out := newGResult()
	types := c.allTypes()
	for _, r := range g.res {
		if !typeMatch(r, types) {
			continue
		}
		switch g.vertex(c, r) {
		case gPass:
			out.pass[r] = true
		case gFail:
			out.fail[r] = true
		default:
			out.unknown[r] = true
		}
	}
	return out
}

func (g *gGraph) vertex(c GCond, r *Resource) int {
	switch c.Kind {
	case "and":
		res := gPass
		for _, s := range c.Sub {
			switch g.vertex(s, r) {
			case gFail:
				return gFail
			case gUnknown:
				res = gUnknown
			}
		}
		return res
	case "or":
		res := gFail
		for _, s := range c.Sub {
			switch g.vertex(s, r) {
			case gPass:
				return gPass
			case gUnknown:
				res = gUnknown
			}
		}
		return res
	case "not":
		switch v := g.vertex(c.Sub[0], r); v {
		case gUnknown:
			return v
		default:
			return 1 - v
		}
	case "filter", "resource":
		return boolResult(typeMatch(r, append(strList(c.Value), c.Types...)))
	case "attribute":
		if !typeMatch(r, c.Types) {
			return gFail
		}
		return attrResult(r, c)
	}
	return gUnknown
}

func boolResult(b bool) int {
	if b {
		return gPass
	}
	return gFail
}

func (g *gGraph) connection(c GCond, excluded, unknown map[*Resource]bool) gResult {
	out := newGResult()
	var a, b []*Resource
	for _, r := range g.res {
		if typeMatch(r, c.Types) {
			a = append(a, r)
		}
		if typeMatch(r, c.Connected) {
			b = append(b, r)
		}
	}
	if len(a) == 0 || len(b) == 0 {
		for _, r := range append(a, b...) {
			out.fail[r] = true
		}
	} else {
		for _, r := range g.res {
			inA, inB := typeMatch(r, c.Types), typeMatch(r, c.Connected)
			for _, o := range g.edges[r] {
				if !(inA && typeMatch(o, c.Connected) || inB && typeMatch(o, c.Types)) {
					continue
				}
				switch {
				case excluded[r] || excluded[o]:
					out.fail[r], out.fail[o] = true, true
				case unknown[r] || unknown[o]:
					out.unknown[r], out.unknown[o] = true, true
				default:
					out.pass[r], out.pass[o] = true, true
				}
			}
		}
		for _, r := range append(a, b...) {
			if !out.pass[r] && !out.unknown[r] {
				out.fail[r] = true
			}
		}
	}
	switch c.Op {
	case "not_exists":
		out.pass, out.fail = out.fail, out.pass
	case "one_exists":
		for r := range out.pass {
			delete(out.fail, r)
			delete(out.unknown, r)
		}
	}
	return out
}

func (g *gGraph) complexConnection(c GCond) gResult {
	out := newGResult()
	present := false
	for _, r := range g.res {
		if typeMatch(r, c.allTypes()) {
			present = true
			break
		}
	}
	if !present && c.Kind == "and" {
		return out
	}
	var conns []GCond
	var filterTypes []string
	for _, s := range c.Sub {
		switch {
		case s.Kind == "filter":
			filterTypes = append(filterTypes, strList(s.Value)...)
		case s.Kind == "connection" || s.hasConnection():
			conns = append(conns, s)
		default:
			r := g.solve(s)
			merge(out, r)
		}
	}
	if c.Kind == "and" {
		for r := range out.pass {
			if out.fail[r] || out.unknown[r] {
				delete(out.pass, r)
			}
		}
		// Connections that touch the filtered types run last, so they see the other failures.
		sort.SliceStable(conns, func(i, j int) bool {
			return !touches(conns[i], filterTypes) && touches(conns[j], filterTypes)
		})
		for _, s := range conns {
			var r gResult
			if s.Kind == "connection" {
				r = g.connection(s, out.fail, out.unknown)
			} else {
				r = g.complexConnection(s)
			}
			merge(out, r)
		}
		for r := range out.fail {
			delete(out.pass, r)
			delete(out.unknown, r)
		}
		for r := range out.unknown {
			delete(out.pass, r)
		}
	} else {
		for _, s := range conns {
			if s.Kind == "connection" {
				merge(out, g.connection(s, nil, nil))
			} else {
				merge(out, g.complexConnection(s))
			}
		}
		for r := range out.pass {
			delete(out.unknown, r)
			delete(out.fail, r)
		}
		for r := range out.unknown {
			delete(out.fail, r)
		}
	}
	if len(filterTypes) > 0 {
		for _, set := range []map[*Resource]bool{out.pass, out.fail, out.unknown} {
			for r := range set {
				if !typeMatch(r, filterTypes) {
					delete(set, r)
				}
			}
		}
	}
	return out
}

func touches(c GCond, types []string) bool {
	for _, t := range append(append([]string{}, c.allTypes()...), c.Connected...) {
		for _, f := range types {
			if t == f {
				return true
			}
		}
	}
	return false
}

func merge(dst, src gResult) {
	for r := range src.pass {
		dst.pass[r] = true
	}
	for r := range src.fail {
		dst.fail[r] = true
	}
	for r := range src.unknown {
		dst.unknown[r] = true
	}
}

// attrResult evaluates one attribute condition; a "*" segment matches any element.
func attrResult(r *Resource, c GCond) int {
	if c.Attr == "resource_type" {
		return boolResult(applyOp(c.Op, r.Type, c.Value))
	}
	if !strings.Contains(c.Attr, "*") && !c.JSONPath {
		v := r.get(c.Attr)
		if v == nil {
			if m := expand(r.Attrs, pathSegs(c.Attr)); len(m) == 1 {
				v = m[0]
			}
		}
		if isUnknown(v) || containsUnknown(v) {
			switch c.Op {
			case "exists", "any", "is_not_empty":
				return gPass
			case "not_exists", "is_empty":
				return gFail
			}
			return gUnknown
		}
		return boolResult(applyOp(c.Op, v, c.Value))
	}
	matches := expand(r.Attrs, pathSegs(c.Attr))
	if len(matches) == 0 {
		return boolResult(applyOp(c.Op, nil, c.Value))
	}
	all := c.Op == "not_contains" || c.JSONPath // every match must satisfy these
	known := 0
	passed := 0
	for _, v := range matches {
		if isUnknown(v) || containsUnknown(v) {
			continue
		}
		known++
		if applyOp(c.Op, v, c.Value) {
			passed++
		}
	}
	switch {
	case all && passed == known && known == len(matches):
		return gPass
	case all && passed < known:
		return gFail
	case !all && passed > 0:
		return gPass
	case known == len(matches):
		return gFail
	}
	return gUnknown
}

func expand(v any, segs []string) []any {
	if len(segs) == 0 {
		return []any{v}
	}
	seg := segs[0]
	if strings.HasPrefix(seg, "?(") {
		var out []any
		for _, e := range jpFilter(seg, anyList(v)) {
			out = append(out, expand(e, segs[1:])...)
		}
		return out
	}
	switch t := v.(type) {
	case string: // a JSON document such as an IAM policy
		var doc any
		if s := strings.TrimSpace(t); (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Unmarshal([]byte(s), &doc) == nil {
			return expand(doc, segs)
		}
		if seg == "*" { // IAM allows "Action": "x" as well as a list
			return expand(t, segs[1:])
		}
	case []any:
		if seg == "*" {
			var out []any
			for _, e := range t {
				out = append(out, expand(e, segs[1:])...)
			}
			return out
		}
		if i, err := strconv.Atoi(seg); err == nil {
			if i < len(t) {
				return expand(t[i], segs[1:])
			}
			return nil
		}
		var out []any
		for _, e := range t {
			out = append(out, expand(e, segs)...)
		}
		return out
	case map[string]any:
		if seg == "*" {
			var out []any
			for _, k := range sortedKeys(t) {
				out = append(out, expand(t[k], segs[1:])...)
			}
			return out
		}
		if seg == "0" && t["0"] == nil {
			return expand(t, segs[1:])
		}
		if e, ok := t[seg]; ok {
			return expand(e, segs[1:])
		}
	}
	return nil
}

// pyStr prints a value in the form policy values are compared in.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case string:
		return t
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func applyOp(op string, v, want any) bool {
	if neg, ok := strings.CutPrefix(op, "not_"); ok && op != "not_exists" {
		return !applyOp(neg, v, want)
	}
	switch op {
	case "exists", "any":
		return v != nil
	case "not_exists":
		return v == nil
	case "equals":
		_, vb := v.(bool)
		_, wb := want.(bool)
		if vb || wb {
			return strings.EqualFold(pyStr(v), pyStr(want))
		}
		return pyStr(v) == pyStr(want)
	case "equals_ignore_case":
		return strings.EqualFold(pyStr(v), pyStr(want))
	case "within":
		if l, ok := want.([]any); ok {
			for _, w := range l {
				if pyStr(w) == pyStr(v) {
					return true
				}
			}
			return false
		}
		return v != nil && strings.Contains(pyStr(want), pyStr(v))
	case "contains":
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				if pyStr(e) == pyStr(want) {
					return true
				}
			}
			return false
		case map[string]any:
			if _, ok := t[pyStr(want)]; ok {
				return true
			}
			for _, e := range t {
				if s, ok := e.(string); ok && strings.Contains(s, pyStr(want)) {
					return true
				}
			}
			return false
		case string:
			return strings.Contains(t, pyStr(want))
		}
		return false
	case "starting_with":
		s, ok := v.(string)
		return ok && strings.HasPrefix(s, pyStr(want))
	case "ending_with":
		s, ok := v.(string)
		return ok && strings.HasSuffix(s, pyStr(want))
	case "regex_match":
		re, err := regexp.Compile(pyStr(want))
		return err == nil && v != nil && re.MatchString(pyStr(v))
	case "greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal":
		if v == nil {
			return false
		}
		a, aok := asFloat(v)
		b, bok := asFloat(want)
		if !aok || !bok {
			s, w := pyStr(v), pyStr(want)
			return map[string]bool{"greater_than": s > w, "greater_than_or_equal": s >= w, "less_than": s < w, "less_than_or_equal": s <= w}[op]
		}
		return map[string]bool{"greater_than": a > b, "greater_than_or_equal": a >= b, "less_than": a < b, "less_than_or_equal": a <= b}[op]
	case "is_true":
		return is(v, true)
	case "is_false":
		return is(v, false)
	case "is_empty":
		return v != nil && empty(v) || isEmptyMap(v)
	case "is_not_empty":
		return !(v != nil && empty(v) || isEmptyMap(v)) && v != nil
	case "length_equals", "length_greater_than", "length_greater_than_or_equal", "length_less_than", "length_less_than_or_equal":
		n := -1
		switch t := v.(type) {
		case string:
			n = len(t)
		case []any:
			n = len(t)
		case map[string]any:
			n = 1
		}
		w, ok := asFloat(want)
		if n < 0 || !ok {
			return false
		}
		f := float64(n)
		return map[string]bool{"length_equals": f == w, "length_greater_than": f > w, "length_greater_than_or_equal": f >= w, "length_less_than": f < w, "length_less_than_or_equal": f <= w}[op]
	case "subset", "intersects":
		have := map[string]bool{}
		for _, e := range anyList(v) {
			have[pyStr(e)] = true
		}
		allowed := map[string]bool{}
		for _, e := range anyList(want) {
			allowed[pyStr(e)] = true
		}
		if op == "intersects" {
			for k := range have {
				if allowed[k] {
					return true
				}
			}
			return false
		}
		for k := range have {
			if !allowed[k] {
				return false
			}
		}
		return v != nil
	}
	return false
}

func isEmptyMap(v any) bool { m, ok := v.(map[string]any); return ok && len(m) == 0 }

func anyList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	if v == nil {
		return nil
	}
	return []any{v}
}

// graphPolicyFindings runs the policies and reports each failing resource.
func graphPolicyFindings(rs []*Resource, policies []*GraphPolicy, id func(*GraphPolicy) string) []Finding {
	if len(policies) == 0 || len(rs) == 0 {
		return nil
	}
	g := newGGraph(rs)
	var out []Finding
	for _, p := range policies {
		res := g.solve(p.Def)
		failed := make([]*Resource, 0, len(res.fail))
		for r := range res.fail {
			failed = append(failed, r)
		}
		sort.Slice(failed, func(i, j int) bool { return failed[i].Address < failed[j].Address })
		for _, r := range failed {
			msg := p.Why
			if msg == "" {
				msg = r.Address + " does not meet: " + p.Title + "."
			}
			f := newFinding(id(p), "", msg, r.Address, r.File, r.Line)
			out = append(out, f)
		}
	}
	return out
}

type graphGenEntry struct {
	Rule
	Def string // the definition as JSON
	Why string // impact, used as the finding message
}

// graphRules are the built-in graph policies' catalog entries.
var graphRules = func() []Rule {
	out := make([]Rule, len(graphGen))
	for i, e := range graphGen {
		out[i] = e.Rule
	}
	return out
}()

var builtinGraph = func() []*GraphPolicy {
	out := make([]*GraphPolicy, 0, len(graphGen))
	for _, e := range graphGen {
		p := &GraphPolicy{ID: e.ID, Title: e.Title, Severity: e.Severity, Why: e.Why}
		if json.Unmarshal([]byte(e.Def), &p.Def) == nil {
			out = append(out, p)
		}
	}
	return out
}()

func init() {
	for ckv, id := range graphIDs {
		foreignRules[ckv] = append(foreignRules[ckv], id)
	}
}

// graphScan runs the built-in graph policies and the user's own (Checkov YAML
// format) and returns their findings and any policies that failed to parse.
func graphScan(rs []*Resource, user []string) ([]Finding, []string) {
	out := graphPolicyFindings(rs, builtinGraph, func(p *GraphPolicy) string { return p.ID })
	var errs []string
	var custom []*GraphPolicy
	for _, src := range user {
		p, err := ParseGraphPolicy(src)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		custom = append(custom, p)
	}
	if len(custom) == 0 {
		return out, errs
	}
	g := newGGraph(rs)
	for _, p := range custom {
		res := g.solve(p.Def)
		for r := range res.fail {
			out = append(out, Finding{RuleID: p.ID, Severity: p.Severity, Category: CatPolicy, Title: p.Title,
				Message: r.Address + " does not meet: " + p.Title + ".", Resource: r.Address, File: r.File, Line: r.Line})
		}
	}
	return out, errs
}
