// Command awsvalgen writes engine/values_aws_gen.go: value constraints (enum,
// pattern, length) the AWS API enforces on Terraform resource arguments.
//
//	go run ./tools/awsvalgen -mappings <tflint-ruleset-aws>/rules/models/mappings \
//	  -models <api-models-aws> -schema <tflint-ruleset-aws>/tools/provider-schema/schema.json
//
// Only plain `attr = Shape` mappings of top-level string arguments are used;
// transforms (uppercase(), map(), ...) are skipped.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

type constraint struct {
	Enum     []string
	Pattern  string
	Min, Max int
}

type shape struct {
	Type    string                     `json:"type"`
	Traits  map[string]json.RawMessage `json:"traits"`
	Members map[string]struct {
		Traits map[string]json.RawMessage `json:"traits"`
	} `json:"members"`
}

// skip lists resource.argument pairs that must not be enforced: the provider
// accepts more than the API enum says, or the corpus showed false positives.
var skip = map[string]string{
	// Region enums go stale as regions launch; the provider passes any region through.
	"aws_cur_report_definition.s3_region":              "region enum",
	"aws_route53_health_check.cloudwatch_alarm_region": "region enum",
	"aws_route53_zone_association.vpc_region":          "region enum",
}

// extra holds documented API values the models leave as a plain String.
var extra = map[string]map[string]constraint{
	"aws_db_instance": {
		// CreateDBInstance Engine, from the RDS API reference; legacy names and the
		// Neptune and DocumentDB engines (same API) are kept so nothing valid is rejected.
		"engine": {Enum: []string{
			"aurora", "aurora-mysql", "aurora-postgresql", "custom-oracle-ee", "custom-oracle-ee-cdb", "custom-oracle-se2",
			"custom-oracle-se2-cdb", "custom-sqlserver-dev", "custom-sqlserver-ee", "custom-sqlserver-se", "custom-sqlserver-web",
			"db2-ae", "db2-se", "mariadb", "mysql", "oracle-ee", "oracle-ee-cdb", "oracle-se", "oracle-se1", "oracle-se2",
			"oracle-se2-cdb", "postgres", "neptune", "docdb", "sqlserver-dev-ee", "sqlserver-dev-se", "sqlserver-ee", "sqlserver-ex", "sqlserver-se",
			"sqlserver-web",
		}},
	},
}

var lookaround = regexp.MustCompile(`\(\?[=!<]`)

func main() {
	mappings := flag.String("mappings", "", "tflint-ruleset-aws rules/models/mappings directory")
	models := flag.String("models", "", "api-models-aws checkout")
	schemaPath := flag.String("schema", "", "provider schema JSON (terraform providers schema -json)")
	out := flag.String("out", "engine/values_aws_gen.go", "output file")
	flag.Parse()

	types := loadSchema(*schemaPath)
	files, _ := filepath.Glob(filepath.Join(*mappings, "*.hcl"))
	table := map[string]map[string]constraint{}
	stats := map[string]int{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		file, diags := hclsyntax.ParseConfig(src, f, hcl.InitialPos)
		if diags.HasErrors() {
			log.Fatal(diags)
		}
		body := file.Body.(*hclsyntax.Body)
		imp, _ := body.Attributes["import"].Expr.Value(nil)
		shapes, ns := loadModel(filepath.Join(*models, strings.TrimPrefix(imp.AsString(), "api-models-aws/")))
		for _, b := range body.Blocks {
			if b.Type != "mapping" || len(b.Labels) != 1 {
				continue
			}
			res := b.Labels[0]
			for attr, a := range b.Body.Attributes {
				tr, d := hcl.AbsTraversalForExpr(a.Expr)
				if d.HasErrors() || len(tr) != 1 {
					stats["skipped: transform or map/list form"]++
					continue
				}
				s, ok := shapes[ns+"#"+tr.RootName()]
				if !ok {
					continue // smithy prelude shape, no constraints
				}
				c, why := toConstraint(s)
				if why != "" {
					stats["skipped: "+why]++
					continue
				}
				if c.Enum == nil && c.Pattern == "" && c.Min == 0 && c.Max == 0 {
					continue
				}
				if t, ok := types[res][attr]; !ok || t != "string" {
					stats["skipped: not a top-level string argument"]++
					continue
				}
				// The provider strips a "/hostedzone/" prefix from Route 53 zone IDs before sending.
				if _, ok := skip[res+"."+attr]; ok || strings.HasPrefix(res, "aws_route53") && strings.HasSuffix(attr, "zone_id") {
					stats["skipped: provider transform or stale enum"]++
					continue
				}
				if table[res] == nil {
					table[res] = map[string]constraint{}
				}
				table[res][attr] = c
			}
		}
	}
	for res, m := range extra {
		for attr, c := range m {
			sort.Strings(c.Enum)
			if table[res] == nil {
				table[res] = map[string]constraint{}
			}
			table[res][attr] = c
		}
	}
	code := render(table, stats)
	if err := os.WriteFile(*out, code, 0o644); err != nil {
		log.Fatal(err)
	}
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%-45s %d\n", k, stats[k])
	}
}

func loadSchema(path string) map[string]map[string]string {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var s struct {
		ProviderSchemas map[string]struct {
			ResourceSchemas map[string]struct {
				Block struct {
					Attributes map[string]struct {
						Type     json.RawMessage `json:"type"`
						Optional bool            `json:"optional"`
						Required bool            `json:"required"`
					} `json:"attributes"`
				} `json:"block"`
			} `json:"resource_schemas"`
		} `json:"provider_schemas"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		log.Fatal(err)
	}
	out := map[string]map[string]string{}
	for _, p := range s.ProviderSchemas {
		for name, r := range p.ResourceSchemas {
			out[name] = map[string]string{}
			for a, at := range r.Block.Attributes {
				if at.Optional || at.Required { // computed-only arguments are never set
					out[name][a] = strings.Trim(string(at.Type), `"`)
				}
			}
		}
	}
	return out
}

func loadModel(path string) (map[string]shape, string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var m struct {
		Shapes map[string]shape `json:"shapes"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Fatal(err)
	}
	for k, s := range m.Shapes {
		if s.Type == "service" {
			return m.Shapes, strings.SplitN(k, "#", 2)[0]
		}
	}
	log.Fatalf("%s: no service shape", path)
	return nil, ""
}

// toConstraint returns the enforceable constraint of a shape, or why it was skipped.
func toConstraint(s shape) (constraint, string) {
	var c constraint
	switch s.Type {
	case "enum":
		for name, m := range s.Members {
			v := name
			if raw, ok := m.Traits["smithy.api#enumValue"]; ok {
				json.Unmarshal(raw, &v)
			}
			c.Enum = append(c.Enum, v)
		}
	case "string":
		if raw, ok := s.Traits["smithy.api#enum"]; ok {
			var items []struct{ Value string }
			json.Unmarshal(raw, &items)
			for _, it := range items {
				c.Enum = append(c.Enum, it.Value)
			}
		}
	default:
		return c, ""
	}
	if raw, ok := s.Traits["smithy.api#length"]; ok {
		var l struct{ Min, Max *int }
		json.Unmarshal(raw, &l)
		if l.Min != nil {
			c.Min = *l.Min
		}
		if l.Max != nil {
			c.Max = *l.Max
		}
	}
	if raw, ok := s.Traits["smithy.api#pattern"]; ok {
		json.Unmarshal(raw, &c.Pattern)
		if lookaround.MatchString(c.Pattern) {
			return c, "pattern uses lookaround"
		}
		if _, err := regexp.Compile(c.Pattern); err != nil {
			return c, "pattern not RE2"
		}
	}
	sort.Strings(c.Enum)
	c.Enum = slices.Compact(c.Enum)
	return c, ""
}

func render(table map[string]map[string]constraint, stats map[string]int) []byte {
	var b bytes.Buffer
	b.WriteString("// Code generated by tools/awsvalgen from the AWS API models (Apache-2.0) and the argument mappings of tflint-ruleset-aws (MPL-2.0); DO NOT EDIT.\n\npackage engine\n\n")
	enums := map[string]string{} // joined values -> var name
	var enumOrder []string
	var body bytes.Buffer
	body.WriteString("var awsValueChecks = map[string][]awsValueCheck{\n")
	types := make([]string, 0, len(table))
	for t := range table {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		attrs := make([]string, 0, len(table[t]))
		for a := range table[t] {
			attrs = append(attrs, a)
		}
		sort.Strings(attrs)
		fmt.Fprintf(&body, "%q: {\n", t)
		for _, a := range attrs {
			c := table[t][a]
			fmt.Fprintf(&body, "{attr: %q", a)
			if c.Enum != nil {
				key := strings.Join(c.Enum, "\x00")
				if enums[key] == "" {
					enums[key] = fmt.Sprintf("awsEnum%d", len(enums))
					enumOrder = append(enumOrder, key)
				}
				fmt.Fprintf(&body, ", enum: %s", enums[key])
				stats["kind: enum"]++
			}
			if c.Pattern != "" {
				fmt.Fprintf(&body, ", pattern: %q", c.Pattern)
				stats["kind: pattern"]++
			}
			if c.Min > 0 {
				fmt.Fprintf(&body, ", min: %d", c.Min)
				stats["kind: min length"]++
			}
			if c.Max > 0 {
				fmt.Fprintf(&body, ", max: %d", c.Max)
				stats["kind: max length"]++
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
