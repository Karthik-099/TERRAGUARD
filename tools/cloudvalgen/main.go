// Command cloudvalgen writes engine/values_azure_gen.go and engine/values_google_gen.go:
// value constraints (enum, pattern) the azurerm and google providers or the cloud
// APIs enforce on Terraform resource arguments.
//
//	go run ./tools/cloudvalgen -azurerm <tflint-ruleset-azurerm> -google <magic-modules>
//
// Azure data comes from the generated rules of tflint-ruleset-azurerm (rules/apispec),
// whose argument mappings and values come from the Azure REST API specs. Google data
// comes from the magic-modules resource definitions (mmv1/products), which the google
// provider is generated from: an Enum property becomes ValidateEnum and a
// validation.regex becomes ValidateRegexp on the same argument.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type constraint struct {
	Enum    []string
	Pattern string
}

type table map[string]map[string]constraint // resource type -> argument path -> constraint

func (t table) add(res, attr string, c constraint) {
	if t[res] == nil {
		t[res] = map[string]constraint{}
	}
	sort.Strings(c.Enum)
	c.Enum = slices.Compact(c.Enum)
	t[res][attr] = c
}

var lookaround = regexp.MustCompile(`\(\?[=!<]`)

// azureSkip lists arguments that must not be enforced.
var azureSkip = map[string]string{
	// Hand-written IDs often use "resourcegroups" lower case, which Azure accepts; the
	// pattern is case-sensitive.
	"azurerm_redis_cache.subnet_id": "case-sensitive resource ID pattern",
}

func main() {
	azurerm := flag.String("azurerm", "", "tflint-ruleset-azurerm checkout")
	google := flag.String("google", "", "magic-modules checkout")
	azOut := flag.String("azure-out", "engine/values_azure_gen.go", "Azure output file")
	gOut := flag.String("google-out", "engine/values_google_gen.go", "Google output file")
	flag.Parse()
	if *azurerm == "" && *google == "" {
		log.Fatal("set -azurerm and/or -google")
	}
	if *azurerm != "" {
		stats := map[string]int{}
		t := loadAzure(filepath.Join(*azurerm, "rules", "apispec"), stats)
		write(*azOut, render(t, "azure", "the Azure REST API specs (MIT) via the generated rules of tflint-ruleset-azurerm (MPL-2.0)", stats), stats)
	}
	if *google != "" {
		stats := map[string]int{}
		t := loadGoogle(filepath.Join(*google, "mmv1", "products"), stats)
		write(*gOut, render(t, "google", "the magic-modules resource definitions (Apache-2.0)", stats), stats)
	}
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
		fmt.Printf("  %-50s %d\n", k, stats[k])
	}
}

// loadAzure reads the literal fields of each generated New...Rule constructor.
func loadAzure(dir string, stats map[string]int) table {
	files, _ := filepath.Glob(filepath.Join(dir, "azurerm_*.go"))
	t := table{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			log.Fatal(err)
		}
		fields := map[string]ast.Expr{}
		ast.Inspect(file, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok {
					fields[k.Name] = kv.Value
				}
			}
			return true
		})
		res, attr := lit(fields["resourceType"]), lit(fields["attributeName"])
		if b := lit(fields["blockType"]); b != "" {
			attr = b + "." + attr
		}
		if res == "" || attr == "" {
			log.Fatalf("%s: no resource type or attribute", f)
		}
		var c constraint
		if e, ok := fields["enum"].(*ast.CompositeLit); ok {
			for _, v := range e.Elts {
				c.Enum = append(c.Enum, lit(v))
			}
		}
		if call, ok := fields["pattern"].(*ast.CallExpr); ok && len(call.Args) == 1 {
			c.Pattern = lit(call.Args[0])
		}
		switch {
		case azureSkip[res+"."+attr] != "":
			stats["skipped: "+azureSkip[res+"."+attr]]++
			continue
		case c.Enum == nil && c.Pattern == "":
			stats["skipped: integer range (not a string constraint)"]++
			continue
		case c.Pattern == "^.*$":
			stats["skipped: pattern matches anything"]++
			continue
		case c.Pattern != "" && !compiles(c.Pattern):
			stats["skipped: pattern not RE2"]++
			continue
		}
		t.add(res, attr, c)
	}
	return t
}

func lit(e ast.Expr) string {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(b.Value)
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func compiles(p string) bool {
	if lookaround.MatchString(p) {
		return false
	}
	_, err := regexp.Compile(p)
	return err == nil
}

type mmProduct struct {
	Name       string `yaml:"name"`
	LegacyName string `yaml:"legacy_name"`
	Versions   []struct {
		Name string `yaml:"name"`
	} `yaml:"versions"`
}

type mmResource struct {
	Name            string    `yaml:"name"`
	LegacyName      string    `yaml:"legacy_name"`
	MinVersion      string    `yaml:"min_version"`
	Exclude         bool      `yaml:"exclude"`
	ExcludeResource bool      `yaml:"exclude_resource"`
	Parameters      []*mmType `yaml:"parameters"`
	Properties      []*mmType `yaml:"properties"`
	VirtualFields   []*mmType `yaml:"virtual_fields"`
}

type mmType struct {
	Name           string    `yaml:"name"`
	Type           string    `yaml:"type"`
	Output         bool      `yaml:"output"`
	Exclude        bool      `yaml:"exclude"`
	MinVersion     string    `yaml:"min_version"`
	ExactVersion   string    `yaml:"exact_version"`
	RemovedMessage string    `yaml:"removed_message"`
	FlattenObject  bool      `yaml:"flatten_object"`
	EnumValues     []string  `yaml:"enum_values"`
	Properties     []*mmType `yaml:"properties"`
	ItemType       *mmType   `yaml:"item_type"`
	Validation     *struct {
		Regex string `yaml:"regex"`
	} `yaml:"validation"`
}

var (
	acronymBoundary = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
	wordBoundary    = regexp.MustCompile(`([a-z\d])([A-Z])`)
)

// underscore is magic-modules' google.Underscore, which names Terraform arguments and resources.
func underscore(s string) string {
	s = acronymBoundary.ReplaceAllString(s, "${1}_${2}")
	s = wordBoundary.ReplaceAllString(s, "${1}_${2}")
	return strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(s))
}

func loadGoogle(dir string, stats map[string]int) table {
	products, _ := filepath.Glob(filepath.Join(dir, "*", "product.yaml"))
	t := table{}
	for _, pf := range products {
		var p mmProduct
		readYAML(pf, &p)
		ga := false
		for _, v := range p.Versions {
			ga = ga || v.Name == "ga"
		}
		if !ga {
			stats["skipped resources: beta-only product"]++
			continue
		}
		prefix := underscore(p.Name)
		if p.LegacyName != "" {
			prefix = underscore(p.LegacyName)
		}
		files, _ := filepath.Glob(filepath.Join(filepath.Dir(pf), "*.yaml"))
		for _, f := range files {
			if filepath.Base(f) == "product.yaml" {
				continue
			}
			var r mmResource
			readYAML(f, &r)
			if r.Name == "" || r.Exclude || r.ExcludeResource || r.MinVersion == "beta" {
				stats["skipped resources: excluded, hand-written or beta"]++
				continue
			}
			res := "google_" + prefix + "_" + underscore(r.Name)
			if r.LegacyName != "" {
				res = r.LegacyName
			}
			for _, list := range [][]*mmType{r.Parameters, r.Properties, r.VirtualFields} {
				walkGoogle(t, res, "", list, stats)
			}
		}
	}
	return t
}

// walkGoogle follows Type.Lineage: nested objects add their name, arrays of
// objects reuse the array's name, flattened objects add nothing.
func walkGoogle(t table, res, prefix string, props []*mmType, stats map[string]int) {
	for _, p := range props {
		if p.Output || p.Exclude || p.MinVersion == "beta" || p.ExactVersion != "" || p.RemovedMessage != "" {
			continue
		}
		path := prefix + underscore(p.Name)
		switch p.Type {
		case "NestedObject":
			if p.FlattenObject {
				walkGoogle(t, res, prefix, p.Properties, stats)
			} else {
				walkGoogle(t, res, path+".", p.Properties, stats)
			}
		case "Array":
			if p.ItemType != nil && p.ItemType.Type == "NestedObject" {
				walkGoogle(t, res, path+".", p.ItemType.Properties, stats)
			}
		case "Enum":
			if len(p.EnumValues) == 0 {
				continue
			}
			t.add(res, path, constraint{Enum: slices.Clone(p.EnumValues)})
		case "String":
			if p.Validation == nil || p.Validation.Regex == "" {
				continue
			}
			if !compiles(p.Validation.Regex) {
				stats["skipped: pattern not RE2"]++
				continue
			}
			t.add(res, path, constraint{Pattern: p.Validation.Regex})
		}
	}
}

func readYAML(path string, v any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, v); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
}

func render(t table, cloud, source string, stats map[string]int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by tools/cloudvalgen from %s; DO NOT EDIT.\n\npackage engine\n\n", source)
	enums := map[string]string{}
	var enumOrder []string
	var body bytes.Buffer
	fmt.Fprintf(&body, "var %sValueChecks = map[string][]awsValueCheck{\n", cloud)
	types := make([]string, 0, len(t))
	for r := range t {
		types = append(types, r)
	}
	sort.Strings(types)
	for _, r := range types {
		attrs := make([]string, 0, len(t[r]))
		for a := range t[r] {
			attrs = append(attrs, a)
		}
		sort.Strings(attrs)
		fmt.Fprintf(&body, "%q: {\n", r)
		for _, a := range attrs {
			c := t[r][a]
			fmt.Fprintf(&body, "{attr: %q", a)
			if c.Enum != nil {
				key := strings.Join(c.Enum, "\x00")
				if enums[key] == "" {
					enums[key] = fmt.Sprintf("%sEnum%d", cloud, len(enums))
					enumOrder = append(enumOrder, key)
				}
				fmt.Fprintf(&body, ", enum: %s", enums[key])
				stats["kind: enum"]++
			}
			if c.Pattern != "" {
				fmt.Fprintf(&body, ", pattern: %q", c.Pattern)
				stats["kind: pattern"]++
			}
			body.WriteString("},\n")
			stats["arguments"]++
		}
		body.WriteString("},\n")
	}
	body.WriteString("}\n")
	stats["resource types"] = len(types)
	stats["distinct enums"] = len(enumOrder)
	for _, key := range enumOrder {
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
