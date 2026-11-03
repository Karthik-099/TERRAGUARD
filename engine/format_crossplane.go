package engine

import (
	"regexp"
	"strconv"
	"strings"
)

// Crossplane managed resources. The Upbound providers (*.aws.upbound.io,
// *.azure.upbound.io, *.gcp.upbound.io) are generated from the Terraform
// providers with Upjet, so spec.forProvider holds the Terraform arguments in
// camelCase; they are converted like Pulumi properties (format_pulumi.go).
// Compositions are read through each resource's base, with patched fields
// treated as decided at deploy time. crossplane-contrib providers
// (*.crossplane.io) use AWS API shapes, so they keep group/kind as the type.

const FormatCrossplane = "crossplane"

func init() { formatParsers[FormatCrossplane] = parseCrossplane }

var crossplaneHead = regexp.MustCompile(`(?m)^\s*"?apiVersion"?\s*:\s*['"]?[a-z0-9.-]+\.(upbound|crossplane)\.io/`)

// isCrossplane reports a file whose head declares a Crossplane API version.
func isCrossplane(head string) bool { return crossplaneHead.MatchString(head) }

// isCrossplaneAPI reports an apiVersion served by Crossplane or its providers.
func isCrossplaneAPI(apiVersion string) bool {
	group, _, _ := strings.Cut(apiVersion, "/")
	return strings.HasSuffix(group, ".upbound.io") || strings.HasSuffix(group, ".crossplane.io")
}

func parseCrossplane(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	var syntax []Finding
	if err != nil {
		syntax = append(syntax, formatSyntax(name, "Crossplane", err))
	}
	var out []*Resource
	for di, d := range docs {
		out = append(out, crossplaneObjects(name, d.value, d.lines, di, "", "")...)
	}
	return out, syntax
}

// crossplaneObjects converts one object; plain Kubernetes objects in the same
// file go to the Kubernetes reader. scope prefixes addresses of composed resources.
func crossplaneObjects(file string, v any, lines map[string]int, doc int, root, scope string) []*Resource {
	m, _ := v.(map[string]any)
	api, _ := m["apiVersion"].(string)
	kind, _ := m["kind"].(string)
	if m == nil || kind == "" {
		return nil
	}
	if !isCrossplaneAPI(api) {
		return k8sObjects(file, v, lines, doc, root)
	}
	group, _, _ := strings.Cut(api, "/")
	name, _ := asString(get(m, "metadata.name"))
	if group == "apiextensions.crossplane.io" && kind == "Composition" {
		return crossplaneComposition(file, m, lines, doc, root, name)
	}
	if name == "" {
		name = "unnamed"
	}
	typ, provider, module := group+"/"+kind, "", ""
	if rest, ok := strings.CutSuffix(group, ".upbound.io"); ok {
		labels := strings.Split(strings.TrimSuffix(rest, ".m"), ".") // .m. marks the namespaced variant
		provider = labels[len(labels)-1]
		if len(labels) > 1 {
			module = labels[0]
		}
		if t := tfResourceType(provider, module, kind); t != "" {
			typ = t
		}
	}
	// initProvider holds values set only at creation; forProvider wins.
	attrs, al := map[string]any{}, subLines(lines, "spec.initProvider")
	ip, _ := get(m, "spec.initProvider").(map[string]any)
	fp, _ := get(m, "spec.forProvider").(map[string]any)
	for k, x := range ip {
		attrs[k] = x
	}
	for k, x := range fp {
		attrs[k] = x
	}
	for k, l := range subLines(lines, "spec.forProvider") {
		al[k] = l
	}
	crossplaneRefs(attrs, "", al)
	r := &Resource{Mode: "managed", Type: typ, Name: name, File: file, Line: k8sFirstLine(lines), Lines: map[string]int{}, Doc: doc, Root: root}
	if typ != group+"/"+kind {
		r.Attrs = tfConv(attrs, tfTypes()[typ], "", "", al, r.Lines)
	} else {
		r.Attrs, r.Lines = attrs, al
	}
	r.Address = typ + "." + join(scope, name)
	return []*Resource{r}
}

// crossplaneRefs turns Upjet references (vpcIdRef, subnetIdRefs,
// subnetIdSelector, passwordSecretRef) into Unknown values of the field they fill.
func crossplaneRefs(m map[string]any, src string, lines map[string]int) {
	for _, k := range sortedKeys(m) {
		x := m[k]
		switch t := x.(type) {
		case map[string]any:
			if !strings.HasSuffix(k, "Ref") && !strings.HasSuffix(k, "Selector") {
				crossplaneRefs(t, join(src, k), lines)
			}
		case []any:
			for i, e := range t {
				if em, ok := e.(map[string]any); ok {
					crossplaneRefs(em, join(src, k)+"."+strconv.Itoa(i), lines)
				}
			}
		}
		var targets []string
		switch {
		case strings.HasSuffix(k, "SecretRef"):
			targets = []string{strings.TrimSuffix(k, "SecretRef")}
		case strings.HasSuffix(k, "Refs"):
			targets = []string{strings.TrimSuffix(k, "Refs") + "s"}
		case strings.HasSuffix(k, "Ref"):
			targets = []string{strings.TrimSuffix(k, "Ref")}
		case strings.HasSuffix(k, "Selector"):
			b := strings.TrimSuffix(k, "Selector")
			targets = []string{b, b + "s"} // a selector fills one value or a list
		default:
			continue
		}
		delete(m, k)
		for _, t := range targets {
			if _, set := m[t]; !set && t != "" {
				m[t] = Unknown{Expr: "crossplane reference " + k}
				if l := lines[join(src, k)]; l != 0 {
					lines[join(src, t)] = l
				}
			}
		}
	}
}

// crossplaneComposition reads each composed resource's base, classic
// (spec.resources) or through function-patch-and-transform (spec.pipeline).
func crossplaneComposition(file string, m map[string]any, lines map[string]int, doc int, root, comp string) []*Resource {
	if comp == "" {
		comp = "composition"
	}
	var out []*Resource
	read := func(list []any, prefix string) {
		for i, e := range list {
			em, _ := e.(map[string]any)
			base, ok := em["base"].(map[string]any)
			if !ok {
				continue
			}
			p := prefix + "." + strconv.Itoa(i)
			if patches, ok := em["patches"].([]any); ok {
				crossplanePatches(base, patches)
			}
			if n, _ := em["name"].(string); n != "" {
				if md, ok := base["metadata"].(map[string]any); ok {
					if md["name"] == nil {
						md["name"] = n
					}
				} else {
					base["metadata"] = map[string]any{"name": n}
				}
			}
			if get(base, "metadata.name") == nil {
				base["metadata"] = map[string]any{"name": "resource-" + strconv.Itoa(i)}
			}
			out = append(out, crossplaneObjects(file, base, subLines(lines, p+".base"), doc, join(root, p+".base"), comp)...)
		}
	}
	if rs, ok := get(m, "spec.resources").([]any); ok {
		read(rs, "spec.resources")
	}
	steps, _ := get(m, "spec.pipeline").([]any)
	for i, s := range steps {
		sm, _ := s.(map[string]any)
		if rs, ok := get(sm, "input.resources").([]any); ok {
			read(rs, "spec.pipeline."+strconv.Itoa(i)+".input.resources")
		}
	}
	return out
}

var patchPathSeg = regexp.MustCompile(`[^.\[\]]+`)

// crossplanePatches marks every field a patch writes as decided at deploy time.
func crossplanePatches(base map[string]any, patches []any) {
	for _, p := range patches {
		pm, _ := p.(map[string]any)
		to, _ := pm["toFieldPath"].(string)
		typ, _ := pm["type"].(string)
		if to == "" || strings.HasPrefix(typ, "To") { // ToCompositeFieldPath writes to the composite
			continue
		}
		segs := patchPathSeg.FindAllString(to, -1)
		var cur any = base
		for i, s := range segs {
			s = strings.Trim(s, `'"`)
			last := i == len(segs)-1
			switch c := cur.(type) {
			case map[string]any:
				if last {
					c[s] = Unknown{Expr: "crossplane patch " + to}
					break
				}
				if _, ok := c[s].(map[string]any); !ok {
					if _, isList := c[s].([]any); !isList {
						if _, num := strconv.Atoi(segs[i+1]); num == nil {
							break // an index into a list that does not exist: nothing to mark
						}
						c[s] = map[string]any{}
					}
				}
				cur = c[s]
			case []any:
				n, err := strconv.Atoi(s)
				if err != nil || n >= len(c) {
					cur = nil
					break
				}
				if last {
					c[n] = Unknown{Expr: "crossplane patch " + to}
					break
				}
				cur = c[n]
			default:
				cur = nil
			}
			if cur == nil {
				break
			}
		}
	}
}
