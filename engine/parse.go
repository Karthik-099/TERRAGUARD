package engine

import (
	"fmt"
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
}

type Ref struct {
	Addr string // var.x, local.y, module.z, data.t.n, t.n
	Line int
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
	Files     map[string][]byte
	Blocks    []*Block
	Resources []*Resource
	Locals    map[string]int // name -> line
	LocalFile map[string]string
	Tfvars    map[string]map[string]int // file -> var name -> line
	State     []string                  // *.tfstate files found in the input
	Syntax    []Finding
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

// Parse reads .tf and .tfvars sources. Syntax errors become blocking findings
// rather than aborting, so one broken file doesn't hide issues in the rest.
func Parse(files map[string]string) *Module {
	m := &Module{Files: map[string][]byte{}, Locals: map[string]int{}, LocalFile: map[string]string{}, Tfvars: map[string]map[string]int{}}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		if strings.Contains(name, ".tfstate") {
			m.State = append(m.State, name)
			continue
		}
		src := []byte(files[name])
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
			continue
		}
		for _, hb := range body.Blocks {
			if hb.Type == "locals" {
				for n, a := range hb.Body.Attributes {
					m.Locals[n] = a.SrcRange.Start.Line
					m.LocalFile[n] = name
				}
			}
			b := &Block{Kind: hb.Type, Labels: hb.Labels, File: name, Line: hb.DefRange().Start.Line,
				Lines: map[string]int{}, body: hb.Body}
			b.Attrs = walkBody(hb.Body, src, "", b.Lines, &b.Refs, nil)
			m.Blocks = append(m.Blocks, b)
			if (hb.Type == "resource" || hb.Type == "data") && len(hb.Labels) == 2 {
				mode := "managed"
				if hb.Type == "data" {
					mode = "data"
				}
				r := &Resource{Address: b.Address(), Mode: mode, Type: hb.Labels[0], Name: hb.Labels[1],
					File: name, Line: b.Line, Attrs: b.Attrs, Lines: b.Lines}
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

func walkBody(body *hclsyntax.Body, src []byte, prefix string, lines map[string]int, refs *[]Ref, skipRoots map[string]bool) map[string]any {
	out := map[string]any{}
	for name, a := range body.Attributes {
		lines[prefix+name] = a.SrcRange.Start.Line
		if name != "provider" && name != "providers" {
			collectRefs(a.Expr, refs, skipRoots)
		}
		out[name] = evalExpr(a.Expr, src)
	}
	counts := map[string]int{}
	for _, nb := range body.Blocks {
		switch nb.Type {
		case "lifecycle":
			// ignore_changes holds bare attribute names, not references.
			out[nb.Type] = []any{walkBody(nb.Body, src, prefix+"lifecycle.0.", lines, new([]Ref), nil)}
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
					walkBody(c.Body, src, prefix+"dynamic."+iter+".", lines, refs, skip)
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
		child := walkBody(nb.Body, src, p+".", lines, refs, skipRoots)
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

func evalExpr(expr hclsyntax.Expression, src []byte) any {
	text := string(expr.Range().SliceBytes(src))
	// Keep jsonencode() arguments structured so policy rules still see literal
	// statements even when one field references another resource.
	if fc, ok := expr.(*hclsyntax.FunctionCallExpr); ok && fc.Name == "jsonencode" && len(fc.Args) == 1 {
		expr = fc.Args[0]
	}
	vars := map[string]cty.Value{}
	for _, t := range expr.Variables() {
		vars[t.RootName()] = cty.DynamicVal
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
