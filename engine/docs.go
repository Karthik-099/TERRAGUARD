package engine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Docs renders terraform-docs style Markdown (inputs, outputs, providers,
// resources, modules) for a module, so READMEs never drift from the code.
func Docs(files map[string]string) string {
	m := Parse(files)
	var b strings.Builder
	cell := func(v any) string {
		switch t := v.(type) {
		case nil:
			return ""
		case Unknown:
			return "`" + strings.ReplaceAll(t.Expr, "|", "\\|") + "`"
		case string:
			return strings.ReplaceAll(t, "|", "\\|")
		}
		j, _ := json.Marshal(v)
		return "`" + string(j) + "`"
	}
	byKind := func(kind string) []*Block {
		var out []*Block
		for _, blk := range m.Blocks {
			if blk.Kind == kind && len(blk.Labels) > 0 {
				out = append(out, blk)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Address() < out[j].Address() })
		return out
	}

	b.WriteString("## Requirements\n\n")
	found := false
	for _, blk := range m.Blocks {
		if blk.Kind != "terraform" {
			continue
		}
		if v, ok := asString(blk.Attrs["required_version"]); ok {
			fmt.Fprintf(&b, "- terraform `%s`\n", v)
			found = true
		}
		for _, rp := range blk.blocksAttr("required_providers") {
			names := make([]string, 0, len(rp))
			for n := range rp {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				pm, _ := rp[n].(map[string]any)
				src, _ := asString(pm["source"])
				ver, _ := asString(pm["version"])
				fmt.Fprintf(&b, "- %s (`%s`) `%s`\n", n, src, ver)
				found = true
			}
		}
	}
	if !found {
		b.WriteString("_No version constraints declared._\n")
	}

	b.WriteString("\n## Inputs\n\n")
	if vars := byKind("variable"); len(vars) > 0 {
		b.WriteString("| Name | Description | Type | Default | Required |\n|---|---|---|---|:---:|\n")
		for _, v := range vars {
			def, has := v.Attrs["default"]
			req := "yes"
			if has {
				req = "no"
			}
			if is(v.Attrs["sensitive"], true) {
				def = "(sensitive)"
			}
			typ := cell(v.Attrs["type"])
			if typ == "" {
				typ = "`any`"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", v.Labels[0], cell(v.Attrs["description"]), typ, cell(def), req)
		}
	} else {
		b.WriteString("_No inputs._\n")
	}

	b.WriteString("\n## Outputs\n\n")
	if outs := byKind("output"); len(outs) > 0 {
		b.WriteString("| Name | Description | Sensitive |\n|---|---|:---:|\n")
		for _, o := range outs {
			s := ""
			if is(o.Attrs["sensitive"], true) {
				s = "yes"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", o.Labels[0], cell(o.Attrs["description"]), s)
		}
	} else {
		b.WriteString("_No outputs._\n")
	}

	if mods := byKind("module"); len(mods) > 0 {
		b.WriteString("\n## Modules\n\n| Name | Source | Version |\n|---|---|---|\n")
		for _, mod := range mods {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", mod.Labels[0], cell(mod.Attrs["source"]), cell(mod.Attrs["version"]))
		}
	}

	b.WriteString("\n## Resources\n\n")
	if len(m.Resources) == 0 {
		b.WriteString("_No resources._\n")
	}
	for _, r := range m.Resources {
		kind := "resource"
		if r.Mode == "data" {
			kind = "data source"
		}
		fmt.Fprintf(&b, "- `%s` (%s)\n", r.Address, kind)
	}
	return b.String()
}
