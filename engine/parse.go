package engine

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// Block is any top-level Terraform block (resource, variable, module, ...).
type Block struct {
	Kind   string
	Labels []string
	File   string
	Line   int
	Attrs  map[string]any
	Lines  map[string]int
	Refs   []Ref
	body   *hclsyntax.Body
	via    map[string]string // attribute path -> var.x or local.y it was resolved from
}

type Ref struct {
	Addr string // var.x, local.y, module.z, data.t.n, t.n
	Line int
}

type localDecl struct {
	name, file string
	line       int
}

func (b *Block) Address() string {
	switch b.Kind {
	case "resource":
		return strings.Join(b.Labels, ".")
	case "data":
		return "data." + strings.Join(b.Labels, ".")
	case "variable":
		return "var." + b.Labels[0]
	case "module":
		return "module." + b.Labels[0]
	}
	return b.Kind + "." + strings.Join(b.Labels, ".")
}

// fixAddr is the hclwrite lookup key used by Fix.Block.
func (b *Block) fixAddr() string { return strings.Join(append([]string{b.Kind}, b.Labels...), ".") }

type Module struct {
	Files      map[string][]byte
	Blocks     []*Block
	Resources  []*Resource
	Locals     map[string]int // name -> line
	LocalFile  map[string]string
	localDecls []localDecl               // every local with its file; names repeat across modules
	Tfvars     map[string]map[string]int // file -> var name -> line
	State      []string                  // *.tfstate files found in the input
	Terragrunt []*Block                  // remote_state blocks from terragrunt.hcl
	Provided   map[string]bool           // "dir|var" set by --var-file or Terragrunt inputs
	Locks      []string                  // .terraform.lock.hcl contents, for provider versions
	JSONLines  map[string]map[int]int    // .tf.json: converted line -> line in the JSON file
	Formats    map[string]string         // non-Terraform files read, and their format
	Syntax     []Finding
}

var funcs = map[string]function.Function{
	"jsonencode": stdlib.JSONEncodeFunc,
	"jsondecode": stdlib.JSONDecodeFunc,
	"merge":      stdlib.MergeFunc,
	"concat":     stdlib.ConcatFunc,
	"lower":      stdlib.LowerFunc,
	"upper":      stdlib.UpperFunc,
	"format":     stdlib.FormatFunc,
	"join":       stdlib.JoinFunc,
	"length":     stdlib.LengthFunc,
	"coalesce":   stdlib.CoalesceFunc,
	"lookup":     stdlib.LookupFunc,
}

// Parse turns syntax errors into findings so one bad file doesn't hide the rest.
// VarFile is a tfvars file passed explicitly (terraform -var-file) for the
// module in Dir. Like Terraform, it overrides terraform.tfvars and auto files.
type VarFile struct {
	Dir    string `json:"dir"`
	Source string `json:"source"`
}

func Parse(files map[string]string, varFiles ...VarFile) *Module {
	m := &Module{Files: map[string][]byte{}, Locals: map[string]int{}, LocalFile: map[string]string{}, Tfvars: map[string]map[string]int{}, Provided: map[string]bool{}, JSONLines: map[string]map[int]int{}, Formats: map[string]string{}}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var sources []parsedFile
	for _, name := range names {
		// OpenTofu reads x.tofu instead of x.tf when both exist.
		if strings.HasSuffix(name, ".tf") {
			if _, ok := files[strings.TrimSuffix(name, ".tf")+".tofu"]; ok {
				continue
			}
		}
		if strings.Contains(name, ".tfstate") {
			m.State = append(m.State, name)
			continue
		}
		if path.Base(name) == ".terraform.lock.hcl" {
			m.Locks = append(m.Locks, files[name]) // read only for provider versions
			continue
		}
		if !isHCLFile(name) {
			if f := detectFormat(name, files[name]); f != "" {
				m.Formats[name] = f
				m.Files[name] = []byte(files[name]) // for inline ignores and context
				if parse := formatParsers[f]; parse != nil {
					rs, syntax := parse(name, files[name])
					for _, r := range rs {
						if r.File == "" {
							r.File = name
						}
						r.Format = f
					}
					m.Resources = append(m.Resources, rs...)
					m.Syntax = append(m.Syntax, syntax...)
				}
			}
			continue
		}
		src := []byte(files[name])
		if strings.HasSuffix(name, ".tf.json") {
			text, lines, err := jsonToHCL(files[name])
			if err != nil {
				m.Syntax = append(m.Syntax, Finding{RuleID: "TG-VAL-001", Severity: High, Category: CatValidate, Blocking: true,
					Title: "HCL syntax error", Message: "Invalid Terraform JSON: " + err.Error(), File: name, Remediation: "Fix the JSON; terraform cannot parse this file."})
				continue
			}
			src, m.JSONLines[name] = []byte(text), lines
		}
		m.Files[name] = src
		f, diags := hclsyntax.ParseConfig(src, name, hcl.InitialPos)
		for _, d := range diags {
			if d.Severity != hcl.DiagError {
				continue
			}
			line := 0
			if d.Subject != nil {
				line = d.Subject.Start.Line
			}
			m.Syntax = append(m.Syntax, Finding{
				RuleID: "TG-VAL-001", Severity: High, Category: CatValidate, Blocking: true,
				Title: "HCL syntax error", Message: strings.TrimSpace(d.Summary + ": " + d.Detail),
				File: name, Line: line, Remediation: "Fix the syntax error; terraform cannot parse this file.",
			})
		}
		if f == nil {
			continue
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		if strings.HasSuffix(name, ".tfvars") {
			vars := map[string]int{}
			for n, a := range body.Attributes {
				vars[n] = a.SrcRange.Start.Line
			}
			m.Tfvars[name] = vars
		}
		sources = append(sources, parsedFile{name: name, src: src, body: body})
	}

	// Second pass: evaluate with var.* and local.* known per directory, so a
	// value moved into a variable or local is still checked.
	ctxs := moduleContexts(sources, varFiles, m)
	for _, pf := range sources {
		if strings.HasSuffix(pf.name, ".tfvars") {
			continue
		}
		if path.Base(pf.name) == "terragrunt.hcl" {
			// Only remote_state matters for checks; inputs were used as variable values above.
			for _, hb := range pf.body.Blocks {
				if hb.Type == "remote_state" {
					b := &Block{Kind: hb.Type, File: pf.name, Line: hb.DefRange().Start.Line, Lines: map[string]int{}, body: hb.Body}
					b.Attrs = walkBody(hb.Body, pf.src, "", b.Lines, &b.Refs, nil, ctxs[path.Dir(pf.name)], nil)
					m.Terragrunt = append(m.Terragrunt, b)
				}
			}
			continue
		}
		name, src, body, ctx := pf.name, pf.src, pf.body, ctxs[path.Dir(pf.name)]
		for _, hb := range body.Blocks {
			if hb.Type == "locals" {
				for n, a := range hb.Body.Attributes {
					m.Locals[n] = a.SrcRange.Start.Line
					m.LocalFile[n] = name
					m.localDecls = append(m.localDecls, localDecl{n, name, a.SrcRange.Start.Line})
				}
			}
			b := &Block{Kind: hb.Type, Labels: hb.Labels, File: name, Line: hb.DefRange().Start.Line,
				Lines: map[string]int{}, body: hb.Body, via: map[string]string{}}
			b.Attrs = walkBody(hb.Body, src, "", b.Lines, &b.Refs, nil, ctx, b.via)
			m.Blocks = append(m.Blocks, b)
			if (hb.Type == "resource" || hb.Type == "data") && len(hb.Labels) == 2 {
				mode := "managed"
				if hb.Type == "data" {
					mode = "data"
				}
				r := &Resource{Address: b.Address(), Mode: mode, Type: hb.Labels[0], Name: hb.Labels[1],
					File: name, Line: b.Line, Attrs: b.Attrs, Lines: b.Lines, Via: b.via}
				seen := map[string]bool{}
				for _, ref := range b.Refs {
					if !seen[ref.Addr] {
						seen[ref.Addr] = true
						r.Refs = append(r.Refs, ref.Addr)
					}
				}
				m.Resources = append(m.Resources, r)
			}
		}
	}
	return m
}

func walkBody(body *hclsyntax.Body, src []byte, prefix string, lines map[string]int, refs *[]Ref, skipRoots map[string]bool, ctx *hcl.EvalContext, via map[string]string) map[string]any {
	out := map[string]any{}
	for name, a := range body.Attributes {
		lines[prefix+name] = a.SrcRange.Start.Line
		if name != "provider" && name != "providers" && name != "ignore_changes" {
			collectRefs(a.Expr, refs, skipRoots)
		}
		out[name] = evalExpr(a.Expr, src, ctx)
		if via != nil && !isUnknown(out[name]) {
			for _, t := range a.Expr.Variables() {
				if r := t.RootName(); (r == "var" || r == "local") && len(t) > 1 {
					if at, ok := t[1].(hcl.TraverseAttr); ok {
						via[prefix+name] = r + "." + at.Name
						break
					}
				}
			}
		}
	}
	counts := map[string]int{}
	for _, nb := range body.Blocks {
		switch nb.Type {
		case "lifecycle":
			// ignore_changes holds bare attribute names, not references.
			out[nb.Type] = []any{walkBody(nb.Body, src, prefix+"lifecycle.0.", lines, refs, skipRoots, ctx, via)}
			continue
		case "dynamic":
			if len(nb.Labels) == 0 {
				continue
			}
			iter := nb.Labels[0]
			if it, ok := nb.Body.Attributes["iterator"]; ok {
				iter = hcl.ExprAsKeyword(it.Expr)
			}
			skip := map[string]bool{iter: true}
			for k := range skipRoots {
				skip[k] = true
			}
			if fe, ok := nb.Body.Attributes["for_each"]; ok {
				collectRefs(fe.Expr, refs, skipRoots)
			}
			for _, c := range nb.Body.Blocks {
				if c.Type == "content" {
					walkBody(c.Body, src, prefix+"dynamic."+iter+".", lines, refs, skip, ctx, via)
				}
			}
			// Generated blocks are unknown until plan time.
			out[nb.Labels[0]] = Unknown{Expr: "dynamic"}
			continue
		}
		idx := counts[nb.Type]
		counts[nb.Type]++
		p := fmt.Sprintf("%s%s.%d", prefix, nb.Type, idx)
		lines[p] = nb.DefRange().Start.Line
		child := walkBody(nb.Body, src, p+".", lines, refs, skipRoots, ctx, via)
		list, _ := out[nb.Type].([]any)
		out[nb.Type] = append(list, child)
	}
	return out
}

func collectRefs(expr hclsyntax.Expression, refs *[]Ref, skipRoots map[string]bool) {
	for _, t := range expr.Variables() {
		root := t.RootName()
		if skipRoots[root] {
			continue
		}
		attr := func(i int) string {
			if i < len(t) {
				if a, ok := t[i].(hcl.TraverseAttr); ok {
					return a.Name
				}
			}
			return ""
		}
		var addr string
		switch root {
		case "count", "each", "self", "path", "terraform":
			continue
		case "var", "local", "module":
			if n := attr(1); n != "" {
				addr = root + "." + n
			}
		case "data":
			if a, b := attr(1), attr(2); a != "" && b != "" {
				addr = "data." + a + "." + b
			}
		default:
			if n := attr(1); n != "" {
				addr = root + "." + n
			}
		}
		if addr != "" {
			*refs = append(*refs, Ref{Addr: addr, Line: t.SourceRange().Start.Line})
		}
	}
}

func evalExpr(expr hclsyntax.Expression, src []byte, known *hcl.EvalContext) any {
	text := string(expr.Range().SliceBytes(src))
	// Keep jsonencode() arguments as data so policy statements stay checkable.
	if fc, ok := expr.(*hclsyntax.FunctionCallExpr); ok && fc.Name == "jsonencode" && len(fc.Args) == 1 {
		expr = fc.Args[0]
	}
	vars := map[string]cty.Value{}
	for _, t := range expr.Variables() {
		vars[t.RootName()] = cty.DynamicVal
		if known != nil {
			if v, ok := known.Variables[t.RootName()]; ok {
				vars[t.RootName()] = v
			}
		}
	}
	v, diags := expr.Value(&hcl.EvalContext{Variables: vars, Functions: funcs})
	if diags.HasErrors() {
		return Unknown{Expr: text}
	}
	return ctyToGo(v, text)
}

func ctyToGo(v cty.Value, text string) any {
	if !v.IsKnown() {
		return Unknown{Expr: text}
	}
	if v.IsNull() {
		return nil
	}
	ty := v.Type()
	switch {
	case ty == cty.String:
		return v.AsString()
	case ty == cty.Number:
		f, _ := v.AsBigFloat().Float64()
		return f
	case ty == cty.Bool:
		return v.True()
	case ty.IsListType() || ty.IsSetType() || ty.IsTupleType():
		out := []any{}
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			out = append(out, ctyToGo(e, text))
		}
		return out
	case ty.IsMapType() || ty.IsObjectType():
		out := map[string]any{}
		for it := v.ElementIterator(); it.Next(); {
			k, e := it.Element()
			out[k.AsString()] = ctyToGo(e, text)
		}
		return out
	}
	return Unknown{Expr: text}
}

type parsedFile struct {
	name string
	src  []byte
	body *hclsyntax.Body
}

// moduleContexts gives each directory the var.* and local.* values that are
// knowable without a plan: tfvars over defaults, and locals built from them.
// Anything depending on resources or unset variables stays unknown.
func moduleContexts(sources []parsedFile, varFiles []VarFile, m *Module) map[string]*hcl.EvalContext {
	type dirVals struct {
		vars   map[string]cty.Value
		inputs map[string]cty.Value   // Terragrunt inputs, passed as TF_VAR_ values (below tfvars)
		auto   map[string]cty.Value   // terraform.tfvars and *.auto.tfvars, as Terraform loads them
		other  map[string][]cty.Value // other .tfvars files; used only when they agree
		locals map[string]hclsyntax.Expression
	}
	dirs := map[string]*dirVals{}
	var calls []moduleCall
	get := func(name string) *dirVals {
		d := path.Dir(name)
		if dirs[d] == nil {
			dirs[d] = &dirVals{vars: map[string]cty.Value{}, inputs: map[string]cty.Value{}, auto: map[string]cty.Value{}, other: map[string][]cty.Value{}, locals: map[string]hclsyntax.Expression{}}
		}
		return dirs[d]
	}
	literal := func(e hclsyntax.Expression) (cty.Value, bool) {
		v, diags := e.Value(&hcl.EvalContext{Functions: funcs})
		return v, !diags.HasErrors() && v.IsWhollyKnown()
	}
	for _, pf := range sources {
		dv := get(pf.name)
		if path.Base(pf.name) == "terragrunt.hcl" {
			if a, ok := pf.body.Attributes["inputs"]; ok {
				if v, diags := a.Expr.Value(&hcl.EvalContext{Functions: funcs}); !diags.HasErrors() && (v.Type().IsObjectType() || v.Type().IsMapType()) && !v.IsNull() {
					for it := v.ElementIterator(); it.Next(); {
						k, ev := it.Element()
						if ev.IsWhollyKnown() {
							dv.inputs[k.AsString()] = ev
						}
					}
				}
			}
			continue
		}
		if strings.HasSuffix(pf.name, ".tfvars") {
			base := path.Base(pf.name)
			for n, a := range pf.body.Attributes {
				if v, ok := literal(a.Expr); ok {
					if base == "terraform.tfvars" || strings.HasSuffix(base, ".auto.tfvars") {
						dv.auto[n] = v
					} else {
						dv.other[n] = append(dv.other[n], v)
					}
				}
			}
			continue
		}
		for _, hb := range pf.body.Blocks {
			switch {
			case hb.Type == "variable" && len(hb.Labels) == 1:
				if a, ok := hb.Body.Attributes["default"]; ok {
					if v, ok := literal(a.Expr); ok {
						dv.vars[hb.Labels[0]] = v
					}
				}
			case hb.Type == "locals":
				for n, a := range hb.Body.Attributes {
					dv.locals[n] = a.Expr
				}
			case hb.Type == "module" && len(hb.Labels) == 1:
				if c, ok := localModuleCall(pf.name, hb); ok {
					calls = append(calls, c)
				}
			}
		}
	}
	out := map[string]*hcl.EvalContext{}
	for d, dv := range dirs {
		for n, v := range dv.inputs {
			dv.vars[n] = v
			m.Provided[d+"|"+n] = true
		}
		for n, vs := range dv.other {
			same := true
			for _, v := range vs[1:] {
				same = same && v.RawEquals(vs[0])
			}
			if same {
				dv.vars[n] = vs[0]
			}
		}
		for n, v := range dv.auto {
			dv.vars[n] = v
		}
		for _, vf := range varFiles {
			if path.Clean(vf.Dir) != d {
				continue
			}
			f, diags := hclsyntax.ParseConfig([]byte(vf.Source), "var-file", hcl.InitialPos)
			if diags.HasErrors() {
				continue
			}
			for n, a := range f.Body.(*hclsyntax.Body).Attributes {
				if v, ok := literal(a.Expr); ok {
					dv.vars[n] = v
				}
				m.Provided[d+"|"+n] = true
			}
		}
		out[d] = evalContext(dv.vars, dv.locals)
	}
	// A local module's variables take the values its callers pass, as in
	// Terraform; when callers disagree the value stays unknown. Nested modules
	// resolve over a few passes.
	for pass := 0; pass < 4 && len(calls) > 0; pass++ {
		passed := map[string]map[string][]cty.Value{} // child dir -> var -> values from each call
		callsTo := map[string]int{}
		for _, c := range calls {
			ctx := out[c.parent]
			if ctx == nil || dirs[c.child] == nil {
				continue
			}
			callsTo[c.child]++
			if passed[c.child] == nil {
				passed[c.child] = map[string][]cty.Value{}
			}
			for n, e := range c.args {
				m.Provided[c.child+"|"+n] = true
				if v, diags := e.Value(ctx); !diags.HasErrors() && v.IsWhollyKnown() {
					passed[c.child][n] = append(passed[c.child][n], v)
				}
			}
		}
		changed := false
		for child, vars := range passed {
			dv := dirs[child]
			for n, vs := range vars {
				same := len(vs) == callsTo[child]
				for _, v := range vs[1:] {
					same = same && v.RawEquals(vs[0])
				}
				if old, had := dv.vars[n]; same && (!had || !old.RawEquals(vs[0])) {
					dv.vars[n] = vs[0]
					changed = true
				}
			}
			out[child] = evalContext(dv.vars, dv.locals)
		}
		if !changed {
			break
		}
	}
	return out
}

// evalContext resolves var.* and local.* for one module directory.
func evalContext(vars map[string]cty.Value, exprs map[string]hclsyntax.Expression) *hcl.EvalContext {
	locals := map[string]cty.Value{}
	ctx := &hcl.EvalContext{Functions: funcs, Variables: map[string]cty.Value{}}
	for pass := 0; pass < 4; pass++ { // locals may build on each other
		ctx.Variables["var"] = cty.ObjectVal(vars)
		ctx.Variables["local"] = cty.ObjectVal(locals)
		added := false
		for n, e := range exprs {
			if _, done := locals[n]; done {
				continue
			}
			if v, diags := e.Value(ctx); !diags.HasErrors() && v.IsWhollyKnown() {
				locals[n] = v
				added = true
			}
		}
		if !added {
			break
		}
	}
	ctx.Variables["local"] = cty.ObjectVal(locals)
	return ctx
}

type moduleCall struct {
	parent, child string
	args          map[string]hclsyntax.Expression
}

// moduleMeta are module block arguments that are not inputs.
var moduleMeta = map[string]bool{"source": true, "version": true, "providers": true, "count": true, "for_each": true, "depends_on": true}

// localModuleCall reads a module block whose source is a path in the repository.
func localModuleCall(file string, b *hclsyntax.Block) (moduleCall, bool) {
	a, ok := b.Body.Attributes["source"]
	if !ok {
		return moduleCall{}, false
	}
	v, diags := a.Expr.Value(nil)
	if diags.HasErrors() || v.Type() != cty.String {
		return moduleCall{}, false
	}
	src := v.AsString()
	if !strings.HasPrefix(src, "./") && !strings.HasPrefix(src, "../") {
		return moduleCall{}, false
	}
	c := moduleCall{parent: path.Dir(file), child: path.Clean(path.Join(path.Dir(file), src)), args: map[string]hclsyntax.Expression{}}
	if _, multi := b.Body.Attributes["for_each"]; multi {
		return moduleCall{}, false // each instance may differ
	}
	if _, multi := b.Body.Attributes["count"]; multi {
		return moduleCall{}, false
	}
	for n, at := range b.Body.Attributes {
		if !moduleMeta[n] {
			c.args[n] = at.Expr
		}
	}
	return c, true
}
