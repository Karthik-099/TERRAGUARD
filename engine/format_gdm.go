package engine

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Google Cloud Deployment Manager configurations. Resources use Google API
// shapes, not Terraform ones, so they keep their own type (gdm_ plus the API
// type with dots as underscores) and their properties as written; the rules
// are in rules_gdm.go. $(ref.name.field) values are decided at deploy time.

const FormatDeploymentManager = "deployment-manager"

func init() { formatParsers[FormatDeploymentManager] = parseGDM }

var (
	gdmResourcesRE = regexp.MustCompile(`(?m)^resources:\s*$`)
	gdmTypeRE      = regexp.MustCompile(`(?m)^\s*(-\s+)?type:\s*['"]?[a-z][a-z0-9]*\.(v\d\w*|alpha|beta)\.[a-zA-Z]+['"]?\s*$`)
	gdmRefRE       = regexp.MustCompile(`\$\(ref\.([^.)]+)`)
)

// isDeploymentManager reports a top-level resources list with API types such as compute.v1.instance.
func isDeploymentManager(head string) bool {
	return gdmResourcesRE.MatchString(head) && gdmTypeRE.MatchString(head)
}

// gdmType is the resource type for an API type: compute.v1.instance -> gdm_compute_v1_instance.
func gdmType(t string) string {
	return "gdm_" + strings.NewReplacer(".", "_", "-", "_", "/", "_", ":", "_").Replace(t)
}

func parseGDM(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	var syntax []Finding
	if err != nil {
		syntax = append(syntax, formatSyntax(name, "Deployment Manager", err))
	}
	var out []*Resource
	for di, d := range docs {
		root, _ := d.value.(map[string]any)
		list, _ := root["resources"].([]any)
		addr := map[string]string{}
		refs := map[*Resource][]string{}
		for i, e := range list {
			obj, _ := e.(map[string]any)
			id, _ := obj["name"].(string)
			typ, _ := obj["type"].(string)
			if id == "" || typ == "" {
				continue
			}
			var named []string
			props, _ := gdmValues(obj["properties"], func(n string) { named = append(named, n) }).(map[string]any)
			if props == nil {
				props = map[string]any{}
			}
			base := "resources." + strconv.Itoa(i)
			r := &Resource{Mode: "managed", Type: gdmType(typ), Name: id, File: name, Line: d.lines[base], Attrs: props,
				Lines: subLines(d.lines, base+".properties"), Doc: di, Root: base}
			r.Address = r.Type + "." + id
			addr[id] = r.Address
			refs[r] = named
			out = append(out, r)
		}
		for r, named := range refs {
			seen := map[string]bool{}
			for _, n := range named {
				if a := addr[n]; a != "" && a != r.Address && !seen[a] {
					seen[a] = true
					r.Refs = append(r.Refs, a)
				}
			}
			sort.Strings(r.Refs)
		}
	}
	return out, syntax
}

// gdmValues turns $(ref.x.y) and template variables into Unknown, calling ref for each referenced resource.
func gdmValues(v any, ref func(string)) any {
	switch t := v.(type) {
	case string:
		if strings.Contains(t, "$(") || strings.Contains(t, "{{") {
			for _, m := range gdmRefRE.FindAllStringSubmatch(t, -1) {
				ref(m[1])
			}
			return Unknown{Expr: t}
		}
	case map[string]any:
		for k, x := range t {
			t[k] = gdmValues(x, ref)
		}
	case []any:
		for i, x := range t {
			t[i] = gdmValues(x, ref)
		}
	}
	return v
}
