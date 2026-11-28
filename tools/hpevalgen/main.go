// Command hpevalgen writes engine/values_hpe_gen.go: the enumerations the HPE
// Terraform provider (HPE/hpe) validates at plan time, read from its Go source.
//
//	go run ./tools/hpevalgen -hpe <terraform-provider-hpe> -schema <schema.json>
//
// Only two validators count, because both run during terraform validate and
// plan: stringvalidator.OneOf (plugin framework) and case-sensitive
// validation.StringInSlice (SDKv2). A validator nested in a combinator such as
// stringvalidator.Any is skipped, since it does not reject a value on its own;
// one inside ValueStringsAre applies to each element of a list or set.
// Arguments are kept only when every value is a literal or a constant of the
// package, and, with -schema (terraform providers schema -json of the same
// version), only when the path exists in the provider's schema as a string or
// a list or set of strings.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type table map[string]map[string][]string // resource type -> argument path -> allowed values

type pkg struct {
	files  []*ast.File
	consts map[string]string
	funcs  map[string]*ast.FuncDecl
}

func loadPkg(dir string, only func(string) bool) *pkg {
	p := &pkg{consts: map[string]string{}, funcs: map[string]*ast.FuncDecl{}}
	names, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	sort.Strings(names)
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") || (only != nil && !only(n)) {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), n, nil, 0)
		if err != nil {
			log.Fatal(err)
		}
		p.files = append(p.files, f)
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					p.funcs[d.Name.Name] = d
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok || d.Tok != token.CONST {
						continue
					}
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							if b, ok := vs.Values[i].(*ast.BasicLit); ok && b.Kind == token.STRING {
								p.consts[name.Name], _ = strconv.Unquote(b.Value)
							}
						}
					}
				}
			}
		}
	}
	return p
}

// str resolves a string literal or a package constant.
func (p *pkg) str(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			s, err := strconv.Unquote(e.Value)
			return s, err == nil
		}
	case *ast.Ident:
		s, ok := p.consts[e.Name]
		return s, ok
	}
	return "", false
}

func (p *pkg) strs(es []ast.Expr) ([]string, bool) {
	out := make([]string, 0, len(es))
	for _, e := range es {
		s, ok := p.str(e)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, len(out) > 0
}

func selector(e ast.Expr) (string, string) {
	if s, ok := e.(*ast.SelectorExpr); ok {
		if x, ok := s.X.(*ast.Ident); ok {
			return x.Name, s.Sel.Name
		}
	}
	return "", ""
}

// walk records the enum validators under n; path is the chain of string map
// keys (attribute names), and blocked is set inside a validator combinator.
func (p *pkg) walk(n ast.Node, path []string, blocked bool, rec func(path []string, vals []string), stats map[string]int) {
	switch n := n.(type) {
	case *ast.KeyValueExpr:
		if k, ok := n.Key.(*ast.BasicLit); ok && k.Kind == token.STRING {
			name, _ := strconv.Unquote(k.Value)
			p.walk(n.Value, append(slices.Clip(path), name), blocked, rec, stats)
			return
		}
		p.walk(n.Value, path, blocked, rec, stats)
		return
	case *ast.CallExpr:
		x, sel := selector(n.Fun)
		switch {
		case x == "stringvalidator" && sel == "OneOf", x == "validation" && sel == "StringInSlice":
			stats["validators seen"]++
			args := n.Args
			if sel == "StringInSlice" {
				cl, ok := args[0].(*ast.CompositeLit)
				ic, _ := args[1].(*ast.Ident)
				if !ok || ic == nil || ic.Name != "false" {
					stats["skipped: case-insensitive or computed list"]++
					return
				}
				args = cl.Elts
			}
			vals, ok := p.strs(args)
			switch {
			case !ok:
				stats["skipped: values not literal"]++
			case blocked:
				stats["skipped: inside a combinator"]++
			case len(path) == 0:
				stats["skipped: no attribute path"]++
			default:
				rec(path, vals)
			}
			return
		case sel == "ValueStringsAre" || (x == "validation" && sel == "ToDiagFunc"):
			// passes each element (or the value) to the inner validator
		case strings.HasSuffix(x, "validator") || x == "validation":
			blocked = true
		}
	}
	ast.Inspect(n, func(c ast.Node) bool {
		if c == n {
			return true
		}
		if c != nil {
			p.walk(c, path, blocked, rec, stats)
		}
		return false
	})
}

// schemaPath reports whether path names a string (or list or set of strings) argument.
func schemaPath(block map[string]any, path []string) bool {
	attrs, _ := block["attributes"].(map[string]any)
	if a, ok := attrs[path[0]].(map[string]any); ok {
		if len(path) == 1 {
			t, _ := json.Marshal(a["type"])
			s := string(t)
			settable := a["optional"] == true || a["required"] == true
			return settable && (s == `"string"` || s == `["list","string"]` || s == `["set","string"]`)
		}
		nt, _ := a["nested_type"].(map[string]any)
		return nt != nil && schemaPath(nt, path[1:])
	}
	bt, _ := block["block_types"].(map[string]any)
	if b, ok := bt[path[0]].(map[string]any); ok && len(path) > 1 {
		inner, _ := b["block"].(map[string]any)
		return schemaPath(inner, path[1:])
	}
	return false
}

func main() {
	src := flag.String("hpe", "", "terraform-provider-hpe checkout")
	schemaFile := flag.String("schema", "", "terraform providers schema -json output with registry.terraform.io/hpe/hpe")
	out := flag.String("out", "engine/values_hpe_gen.go", "output file")
	verbose := flag.Bool("v", false, "log skipped arguments")
	flag.Parse()
	if *src == "" {
		log.Fatal("set -hpe")
	}
	var schemas map[string]any
	if *schemaFile != "" {
		b, err := os.ReadFile(*schemaFile)
		if err != nil {
			log.Fatal(err)
		}
		var doc struct {
			Providers map[string]struct {
				Resources map[string]any `json:"resource_schemas"`
			} `json:"provider_schemas"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			log.Fatal(err)
		}
		schemas = doc.Providers["registry.terraform.io/hpe/hpe"].Resources
	}
	docs, _ := filepath.Glob(filepath.Join(*src, "docs", "resources", "*.md"))
	types := map[string]bool{}
	for _, d := range docs {
		types["hpe_"+strings.TrimSuffix(filepath.Base(d), ".md")] = true
	}
	stats := map[string]int{}
	t := table{}
	add := func(res string) func([]string, []string) {
		return func(path, vals []string) {
			a := strings.Join(path, ".")
			if schemas != nil {
				blk, _ := schemas[res].(map[string]any)
				inner, _ := blk["block"].(map[string]any)
				if inner == nil || !schemaPath(inner, path) {
					stats["skipped: path not in the provider schema"]++
					if *verbose {
						log.Printf("not in schema: %s.%s", res, a)
					}
					return
				}
			}
			if t[res] == nil {
				t[res] = map[string][]string{}
			}
			if prev, ok := t[res][a]; ok && !slices.Equal(prev, vals) {
				stats["skipped: conflicting validators"]++
				t[res][a] = nil // two schemas disagree: keep neither
				return
			}
			t[res][a] = vals
		}
	}
	squash := func(s string) string { return strings.ReplaceAll(s, "_", "") }

	// Plugin framework resources: one directory per resource type.
	fw := filepath.Join(*src, "morpheus", "framework", "resources")
	dirs, _ := os.ReadDir(fw)
	for _, d := range dirs {
		var match []string
		for ty := range types {
			if rest, ok := strings.CutPrefix(ty, "hpe_morpheus_"); ok && squash(rest) == d.Name() {
				match = append(match, ty)
			}
		}
		if len(match) != 1 {
			stats["skipped: framework directory without one resource type"]++
			continue
		}
		p := loadPkg(filepath.Join(fw, d.Name()), nil)
		for _, f := range p.files {
			p.walk(f, nil, false, add(match[0]), stats)
		}
	}
	// OpsRamp resources: one file per resource type.
	op := filepath.Join(*src, "opsramp", "resources")
	files, _ := filepath.Glob(filepath.Join(op, "*.go"))
	sort.Strings(files)
	all := loadPkg(op, nil)
	for _, f := range files {
		ty := "hpe_opsramp_" + strings.TrimSuffix(filepath.Base(f), ".go")
		if !types[ty] {
			continue
		}
		p := loadPkg(op, func(n string) bool { return n == f })
		p.consts = all.consts
		for _, af := range p.files {
			p.walk(af, nil, false, add(ty), stats)
		}
	}
	// SDKv2 resources: the ResourcesMap in morpheus/sdkv2/provider.go names the constructor.
	prov, err := parser.ParseFile(token.NewFileSet(), filepath.Join(*src, "morpheus", "sdkv2", "provider.go"), nil, 0)
	if err != nil {
		log.Fatal(err)
	}
	imports := map[string]string{}
	for _, im := range prov.Imports {
		ip, _ := strconv.Unquote(im.Path.Value)
		name := filepath.Base(ip)
		if im.Name != nil {
			name = im.Name.Name
		}
		if rest, ok := strings.CutPrefix(ip, "github.com/HPE/terraform-provider-hpe/"); ok {
			imports[name] = filepath.Join(*src, rest)
		}
	}
	pkgs := map[string]*pkg{}
	ast.Inspect(prov, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		k, ok := kv.Key.(*ast.BasicLit)
		call, isCall := kv.Value.(*ast.CallExpr)
		if !ok || !isCall {
			return true
		}
		ty, _ := strconv.Unquote(k.Value)
		x, fn := selector(call.Fun)
		if !types[ty] || imports[x] == "" || !strings.Contains(imports[x], "/resources/") {
			return true
		}
		p := pkgs[x]
		if p == nil {
			p = loadPkg(imports[x], nil)
			pkgs[x] = p
		}
		if d := p.funcs[fn]; d != nil {
			p.walk(d.Body, nil, false, add(ty), stats)
		} else {
			stats["skipped: SDKv2 constructor not found"]++
		}
		return false
	})
	write(*out, render(t, stats), stats)
}

func render(t table, stats map[string]int) []byte {
	var b, body bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by tools/hpevalgen from the terraform-provider-hpe source (MPL-2.0); DO NOT EDIT.\n\npackage engine\n\n")
	enums := map[string]string{}
	var order []string
	body.WriteString("var hpeValueChecks = map[string][]awsValueCheck{\n")
	types := make([]string, 0, len(t))
	for r := range t {
		types = append(types, r)
	}
	sort.Strings(types)
	kept := 0
	for _, r := range types {
		attrs := make([]string, 0, len(t[r]))
		for a, v := range t[r] {
			if v != nil {
				attrs = append(attrs, a)
			}
		}
		if len(attrs) == 0 {
			continue
		}
		kept++
		sort.Strings(attrs)
		fmt.Fprintf(&body, "%q: {\n", r)
		for _, a := range attrs {
			vals := slices.Clone(t[r][a])
			sort.Strings(vals)
			vals = slices.Compact(vals)
			key := strings.Join(vals, "\x00")
			if enums[key] == "" {
				enums[key] = fmt.Sprintf("hpeEnum%d", len(enums))
				order = append(order, key)
			}
			fmt.Fprintf(&body, "{attr: %q, enum: %s},\n", a, enums[key])
			stats["arguments"]++
		}
		body.WriteString("},\n")
	}
	body.WriteString("}\n")
	stats["resource types"] = kept
	stats["distinct enums"] = len(order)
	for _, key := range order {
		fmt.Fprintf(&b, "var %s = []string{", enums[key])
		for _, v := range strings.Split(key, "\x00") {
			fmt.Fprintf(&b, "%q, ", v)
		}
		b.WriteString("}\n")
	}
	b.WriteString("\n")
	b.Write(body.Bytes())
	code, err := format.Source(b.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	return code
}

func write(path string, code []byte, stats map[string]int) {
	if err := os.WriteFile(path, code, 0o644); err != nil {
		log.Fatal(err)
	}
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println(path)
	for _, k := range keys {
		fmt.Printf("  %-55s %d\n", k, stats[k])
	}
}
