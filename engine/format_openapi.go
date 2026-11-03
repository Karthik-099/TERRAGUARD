package engine

import (
	"sort"
	"strings"
)

func init() { formatParsers[FormatOpenAPI] = parseOpenAPI }

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// parseOpenAPI reads OpenAPI 3.x and Swagger 2.0 documents into one
// openapi_document (servers or schemes, security, security schemes) and one
// openapi_operation per method and path, whose Attrs carry the operation, its
// parameters (path-level ones merged in), and "effective_security": the
// operation's own requirement, or the document's when it sets none.
func parseOpenAPI(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	if err != nil {
		return nil, []Finding{formatSyntax(name, "OpenAPI", err)}
	}
	var out []*Resource
	for _, d := range docs {
		root, ok := d.value.(map[string]any)
		if !ok {
			continue
		}
		version, _ := asString(root["openapi"])
		if version == "" {
			version, _ = asString(root["swagger"])
		}
		doc := &Resource{Type: "openapi_document", Name: name, Address: "openapi_document." + name, File: name, Line: 1,
			Attrs: root, Lines: d.lines}
		out = append(out, doc)
		schemes := map[string]any{}
		if c, ok := root["components"].(map[string]any); ok {
			if s, ok := c["securitySchemes"].(map[string]any); ok {
				schemes = s
			}
		}
		if s, ok := root["securityDefinitions"].(map[string]any); ok {
			schemes = s
		}
		paths, _ := root["paths"].(map[string]any)
		keys := make([]string, 0, len(paths))
		for k := range paths {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, p := range keys {
			item, _ := paths[p].(map[string]any)
			shared, _ := item["parameters"].([]any)
			for _, method := range httpMethods {
				op, ok := item[method].(map[string]any)
				if !ok {
					continue
				}
				attrs := map[string]any{}
				for k, v := range op {
					attrs[k] = v
				}
				params, _ := op["parameters"].([]any)
				attrs["parameters"] = append(append([]any{}, shared...), params...)
				attrs["method"], attrs["path"], attrs["openapi_version"] = method, p, version
				attrs["security_schemes"] = schemes
				if sec, ok := op["security"]; ok {
					attrs["effective_security"] = sec
				} else if sec, ok := root["security"]; ok {
					attrs["effective_security"] = sec
				}
				prefix := "paths." + p + "." + method
				out = append(out, &Resource{Type: "openapi_operation", Name: strings.ToUpper(method) + " " + p,
					Address: "openapi_operation." + strings.ToUpper(method) + " " + p, File: name,
					Line: d.lines[prefix], Attrs: attrs, Lines: subLines(d.lines, prefix)})
			}
		}
	}
	return out, nil
}
