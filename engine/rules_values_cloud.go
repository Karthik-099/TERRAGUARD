package engine

//go:generate go run ../tools/cloudvalgen -azure-out values_azure_gen.go -google-out values_google_gen.go -azurerm $TFLINT_AZURERM -google $MAGIC_MODULES

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var cloudValueRules = []Rule{
	{ID: "TG-VAL-021", Title: "Value Azure rejects", Severity: High, Category: CatValidate, CWE: "CWE-20", Blocking: true,
		Types: valueTypes(azureValueChecks), Remediation: "Use a value the Azure API accepts; the apply fails with a validation error otherwise.",
		Check: func(r *Resource) []Hit { return checkCloudValues(r, azureValueChecks, "Azure rejects it during apply") }},
	{ID: "TG-VAL-022", Title: "Value Google Cloud rejects", Severity: High, Category: CatValidate, CWE: "CWE-20", Blocking: true,
		Types: valueTypes(googleValueChecks), Remediation: "Use a value the google provider accepts; terraform validate and apply fail otherwise.",
		Check: func(r *Resource) []Hit {
			return checkCloudValues(r, googleValueChecks, "the google provider rejects it at plan time")
		}},
}

func valueTypes(table map[string][]awsValueCheck) []string {
	out := make([]string, 0, len(table))
	for t := range table {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// checkCloudValues applies the AWS rule's constraint logic to a table whose attr may be
// a dotted path through nested blocks (block.attr).
func checkCloudValues(r *Resource, table map[string][]awsValueCheck, outcome string) []Hit {
	if r.Mode == "data" || r.Format != "" {
		return nil
	}
	var hits []Hit
	for _, c := range table[r.Type] {
		eachString(r.Attrs, strings.Split(c.attr, "."), "", func(path, v string) {
			if v == "" { // empty usually means unset
				return
			}
			cc := c
			// As in TG-VAL-020: only the whole-value enum check is safe for values built
			// from a variable or documents the provider normalizes.
			if t := strings.TrimSpace(v); r.via(path) != "" || strings.ContainsAny(v, "\r\n") || strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
				cc = awsValueCheck{attr: c.attr, enum: c.enum}
			}
			if msg := cc.problem(v); msg != "" {
				hits = append(hits, Hit{Path: path, Msg: fmt.Sprintf("%s = %q: %s; %s.", c.attr, v, msg, outcome)})
			}
		})
	}
	return hits
}

// eachString calls fn for every literal string at parts below attrs, descending into
// every instance of a repeated block; Unknown values and dynamic blocks are skipped.
func eachString(attrs map[string]any, parts []string, prefix string, fn func(path, v string)) {
	v, ok := attrs[parts[0]]
	if !ok {
		return
	}
	if len(parts) == 1 {
		if s, ok := v.(string); ok {
			fn(prefix+parts[0], s)
		}
		return
	}
	list, _ := v.([]any)
	for i, e := range list {
		if m, ok := e.(map[string]any); ok {
			eachString(m, parts[1:], prefix+parts[0]+"."+strconv.Itoa(i)+".", fn)
		}
	}
}
