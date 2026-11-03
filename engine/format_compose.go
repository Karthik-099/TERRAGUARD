package engine

import (
	"path"
	"sort"
)

// A compose file becomes one compose_service per service (Attrs: the
// service mapping as written, Lines relative to it) and one compose for the
// whole file (volumes, networks, and services reduced to their volumes), for
// checks across services.

func init() { formatParsers[FormatCompose] = parseCompose }

func parseCompose(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	if err != nil {
		return nil, []Finding{formatSyntax(name, "Compose", err)}
	}
	var out []*Resource
	for _, d := range docs {
		doc, ok := d.value.(map[string]any)
		if !ok {
			continue
		}
		services, _ := doc["services"].(map[string]any)
		if services == nil {
			continue
		}
		attrs := ciCopy(doc)
		uses := map[string]any{} // only the volumes; the rest of each service is on compose_service
		for k, v := range services {
			m, _ := v.(map[string]any)
			uses[k] = map[string]any{"volumes": m["volumes"]}
		}
		attrs["services"] = uses
		file := &Resource{Type: "compose", Name: path.Base(name), Address: "compose." + path.Base(name), File: name, Line: 1, Attrs: attrs, Lines: d.lines, Mode: "managed"}
		out = append(out, file)
		names := make([]string, 0, len(services))
		for k := range services {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, sname := range names {
			m, ok := services[sname].(map[string]any)
			if !ok {
				m = map[string]any{}
			}
			out = append(out, &Resource{Type: "compose_service", Name: sname, Address: "compose_service." + sname, File: name,
				Line: d.lines["services."+sname], Attrs: m, Lines: subLines(d.lines, "services."+sname), Mode: "managed"})
		}
	}
	return out, nil
}
