package engine

import (
	"bytes"
	"strings"

	"github.com/zclconf/go-cty/cty"
)

// HPE Morpheus app blueprints and spec templates carry a whole template inline
// (blueprint_content, spec_content). A literal one (heredoc or plain string) is
// scanned with the parser for its kind, and its findings point into the .tf file.
// file() and templatefile() values are not literals: the referenced file is
// scanned on its own when it is in the scanned folder.

// embeddedKind says which attribute holds the template and, from source_type,
// which virtual file suffix makes the engine read it as the right format.
// A suffix of "?" means the source_type only says "inline": sniff JSON or not.
type embeddedKind struct {
	attr string
	ext  map[string]string
}

var embeddedKinds = map[string]embeddedKind{
	"hpe_morpheus_app_blueprint_terraform":       {"blueprint_content", map[string]string{"hcl": ".tf", "json": ".tf.json"}},
	"hpe_morpheus_app_blueprint_cloud_formation": {"blueprint_content", map[string]string{"json": ".json", "yaml": ".yaml"}},
	"hpe_morpheus_app_blueprint_arm":             {"blueprint_content", map[string]string{"json": ".json"}},
	"hpe_morpheus_app_blueprint_kubernetes":      {"blueprint_content", map[string]string{"yaml": ".yaml"}},
	// _helm blueprints and spec templates take only a repository: no inline chart.
	"hpe_morpheus_spec_template_terraform":       {"spec_content", map[string]string{"local": "?.tf"}},
	"hpe_morpheus_spec_template_cloud_formation": {"spec_content", map[string]string{"local": "?.yaml"}},
	"hpe_morpheus_spec_template_arm":             {"spec_content", map[string]string{"local": ".json"}},
	"hpe_morpheus_spec_template_kubernetes":      {"spec_content", map[string]string{"local": ".yaml"}},
}

// sniffExt turns "?.tf" or "?.yaml" into the JSON suffix when the content is JSON.
func sniffExt(ext, body string) string {
	if !strings.HasPrefix(ext, "?") {
		return ext
	}
	ext = ext[1:]
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		if ext == ".tf" {
			return ".tf.json"
		}
		return ".json"
	}
	return ext
}

// embeddedFindings scans the templates inside blueprint resources.
func embeddedFindings(m *Module, in Input) []Finding {
	var out []Finding
	for _, b := range m.Blocks {
		if b.Kind != "resource" || len(b.Labels) != 2 || b.body == nil {
			continue
		}
		kind := embeddedKinds[b.Labels[0]]
		st, _ := b.Attrs["source_type"].(string)
		ext := kind.ext[strings.ToLower(st)]
		a := b.body.Attributes[kind.attr]
		if ext == "" || a == nil || len(a.Expr.Variables()) > 0 {
			continue
		}
		v, diags := a.Expr.Value(nil)
		if diags.HasErrors() || !v.Type().Equals(cty.String) || v.IsNull() {
			continue
		}
		// A heredoc's content starts on the line after <<EOF.
		first := a.Expr.Range().Start.Line
		if src := m.Files[b.File]; a.Expr.Range().Start.Byte < len(src) && bytes.HasPrefix(src[a.Expr.Range().Start.Byte:], []byte("<<")) {
			first++
		}
		ext = sniffExt(ext, v.AsString())
		where := b.Address() + "." + kind.attr
		name := b.File + "#" + where + ext
		sub := Scan(Input{Files: map[string]string{name: v.AsString()}, NoBuiltinSchema: in.NoBuiltinSchema})
		for _, f := range sub.Findings {
			// Syntax errors: a malformed template is reported by Morpheus, not here.
			// Raw secret patterns: the outer secret scan already reads the heredoc text.
			if f.File != name || f.RuleID == "TG-VAL-001" || strings.HasPrefix(f.RuleID, "TG-SECRET-") {
				continue
			}
			f.Message = "In " + where + ": " + f.Message
			f.File, f.Resource = b.File, b.Address()
			f.Line = first + max(f.Line, 1) - 1
			// shortcut: auto-fixes inside a heredoc are dropped, an offset edit there is risky; map Fix ranges if users ask.
			f.Fix = nil
			out = append(out, f)
		}
	}
	return out
}
