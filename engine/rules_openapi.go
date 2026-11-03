package engine

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

var (
	oasDocT = []string{"openapi_document"}
	oasOpT  = []string{"openapi_operation"}
)

var writeMethods = map[string]bool{"post": true, "put": true, "patch": true, "delete": true}

// oasSecured reports whether an operation has a non-empty security requirement.
func oasSecured(a map[string]any) (secured, explicitNone bool) {
	sec, ok := a["effective_security"].([]any)
	if !ok {
		return false, false
	}
	for _, req := range sec {
		if m, ok := req.(map[string]any); ok && len(m) > 0 {
			return true, false
		}
	}
	return false, true // security: [] or [{}] turns authentication off
}

func oasSchemes(r *Resource) map[string]any {
	if s, ok := r.Attrs["security_schemes"].(map[string]any); ok {
		return s
	}
	if c, ok := r.Attrs["components"].(map[string]any); ok {
		if s, ok := c["securitySchemes"].(map[string]any); ok {
			return s
		}
	}
	s, _ := r.Attrs["securityDefinitions"].(map[string]any)
	return s
}

// oasInputs walks request parameters and the request body schema.
func oasInputs(r *Resource, visit func(path string, schema map[string]any)) {
	params, _ := r.Attrs["parameters"].([]any)
	for i, p := range params {
		m, _ := p.(map[string]any)
		if m == nil || m["$ref"] != nil {
			continue
		}
		if s, ok := m["schema"].(map[string]any); ok {
			visit(fmt.Sprintf("parameters.%d", i), s)
		} else if _, ok := m["type"]; ok { // Swagger 2.0 keeps the type on the parameter
			visit(fmt.Sprintf("parameters.%d", i), m)
		}
	}
	body, _ := r.Attrs["requestBody"].(map[string]any)
	content, _ := body["content"].(map[string]any)
	for _, mt := range sortedKeys(content) {
		c, _ := content[mt].(map[string]any)
		if s, ok := c["schema"].(map[string]any); ok {
			oasWalkSchema("requestBody.content."+mt+".schema", s, 0, visit)
		}
	}
}

func oasWalkSchema(path string, s map[string]any, depth int, visit func(string, map[string]any)) {
	if depth > 12 || s["$ref"] != nil {
		return
	}
	visit(path, s)
	props, _ := s["properties"].(map[string]any)
	for _, k := range sortedKeys(props) {
		if ps, ok := props[k].(map[string]any); ok {
			oasWalkSchema(path+".properties."+k, ps, depth+1, visit)
		}
	}
	if items, ok := s["items"].(map[string]any); ok {
		oasWalkSchema(path+".items", items, depth+1, visit)
	}
}

var openapiRules = []Rule{
	{ID: "TG-OAS-001", Title: "Operation has no authentication", Severity: Medium, Category: CatSecurity, CWE: "CWE-306", Types: oasOpT,
		Remediation: "Add a security requirement to the operation, or a global one in the document's security section.",
		Check: func(r *Resource) []Hit {
			secured, explicitNone := oasSecured(r.Attrs)
			if secured || explicitNone {
				return nil // explicit opt-outs are TG-OAS-002
			}
			sev := Low
			if m, _ := asString(r.Attrs["method"]); writeMethods[m] {
				sev = Medium
			}
			return []Hit{{Path: "", Sev: sev, Msg: "No security requirement applies, so anyone who can reach the API can call it."}}
		}},
	{ID: "TG-OAS-002", Title: "Write operation turns authentication off", Severity: High, Category: CatSecurity, CWE: "CWE-306", Types: oasOpT,
		Remediation: "Remove security: [] from the operation, or name the scheme that protects it.",
		Check: func(r *Resource) []Hit {
			m, _ := asString(r.Attrs["method"])
			if _, none := oasSecured(r.Attrs); none && writeMethods[m] {
				return []Hit{{Path: "security", Msg: "An empty security requirement lets anonymous callers change data."}}
			}
			return nil
		}},
	{ID: "TG-OAS-003", Title: "API is served over plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319", Types: oasDocT,
		Remediation: "Serve the API only over HTTPS: use https:// server URLs (OpenAPI 3) or schemes: [https] (Swagger 2.0).",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			servers, _ := r.Attrs["servers"].([]any)
			for i, s := range servers {
				m, _ := s.(map[string]any)
				raw, _ := asString(m["url"])
				if u, err := url.Parse(raw); err == nil && u.Scheme == "http" && !oasLocal(u.Hostname()) {
					hits = append(hits, Hit{Path: fmt.Sprintf("servers.%d.url", i), Msg: raw + " sends credentials and data unencrypted."})
				}
			}
			if contains(asStrings(r.Attrs["schemes"]), "http") {
				hits = append(hits, Hit{Path: "schemes", Msg: "The http scheme sends credentials and data unencrypted."})
			}
			return hits
		}},
	{ID: "TG-OAS-004", Title: "API key is sent in the query string", Severity: Medium, Category: CatSecurity, CWE: "CWE-598", Types: oasDocT,
		Remediation: "Send API keys in a header (in: header) so they do not end up in logs, browser history and proxies.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			schemes := oasSchemes(r)
			for _, k := range sortedKeys(schemes) {
				s, _ := schemes[k].(map[string]any)
				if t, _ := asString(s["type"]); t == "apiKey" {
					if in, _ := asString(s["in"]); in == "query" {
						hits = append(hits, Hit{Path: oasSchemePath(r, k), Msg: "Scheme " + k + " puts the key in URLs, which are logged by servers and proxies."})
					}
				}
			}
			return hits
		}},
	{ID: "TG-OAS-005", Title: "Security scheme uses HTTP basic authentication", Severity: Low, Category: CatSecurity, CWE: "CWE-522", Types: oasDocT,
		Remediation: "Prefer tokens (OAuth 2, bearer) over passwords sent with every request.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			schemes := oasSchemes(r)
			for _, k := range sortedKeys(schemes) {
				s, _ := schemes[k].(map[string]any)
				t, _ := asString(s["type"])
				sc, _ := asString(s["scheme"])
				if t == "basic" || t == "http" && strings.EqualFold(sc, "basic") {
					hits = append(hits, Hit{Path: oasSchemePath(r, k), Msg: "Scheme " + k + " sends a reusable password with every request."})
				}
			}
			return hits
		}},
	{ID: "TG-OAS-006", Title: "OAuth 2 implicit or password flow is allowed", Severity: Medium, Category: CatSecurity, CWE: "CWE-287", Types: oasDocT,
		Remediation: "Use the authorization code flow with PKCE; the implicit and password flows are deprecated by the OAuth 2.0 Security Best Current Practice.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			schemes := oasSchemes(r)
			for _, k := range sortedKeys(schemes) {
				s, _ := schemes[k].(map[string]any)
				flows, _ := s["flows"].(map[string]any)
				flow, _ := asString(s["flow"]) // Swagger 2.0
				for _, f := range []string{"implicit", "password"} {
					if _, ok := flows[f]; ok || flow == f {
						hits = append(hits, Hit{Path: oasSchemePath(r, k), Msg: "Scheme " + k + " allows the " + f + " flow, which exposes tokens or passwords to the client."})
					}
				}
			}
			return hits
		}},
	{ID: "TG-OAS-007", Title: "Security requirement names an undefined scheme", Severity: High, Category: CatValidate, CWE: "CWE-1188", Types: oasOpT,
		Remediation: "Define the scheme under components.securitySchemes (or securityDefinitions), or fix the name.",
		Check: func(r *Resource) []Hit {
			sec, _ := r.Attrs["effective_security"].([]any)
			schemes, _ := r.Attrs["security_schemes"].(map[string]any)
			var missing []string
			for _, req := range sec {
				m, _ := req.(map[string]any)
				for name := range m {
					if _, ok := schemes[name]; !ok {
						missing = append(missing, name)
					}
				}
			}
			if len(missing) == 0 {
				return nil
			}
			sort.Strings(missing)
			return []Hit{{Path: "security", Msg: "No scheme named " + strings.Join(missing, ", ") + " is defined, so the requirement cannot be enforced."}}
		}},
	{ID: "TG-OAS-008", Title: "Input has no size limit", Severity: Low, Category: CatSecurity, CWE: "CWE-770", Types: oasOpT,
		Remediation: "Give string inputs maxLength, arrays maxItems and numbers a maximum, so oversized input is rejected at the edge.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			oasInputs(r, func(p string, s map[string]any) {
				if enum, _ := s["enum"].([]any); len(enum) > 0 || s["format"] == "date-time" || s["format"] == "uuid" || s["format"] == "date" {
					return
				}
				t, _ := asString(s["type"])
				switch {
				case t == "string" && s["maxLength"] == nil && s["pattern"] == nil:
					hits = append(hits, Hit{Path: p, Msg: "String input with no maxLength accepts arbitrarily large values."})
				case t == "array" && s["maxItems"] == nil:
					hits = append(hits, Hit{Path: p, Msg: "Array input with no maxItems accepts arbitrarily many elements."})
				case (t == "integer" || t == "number") && s["maximum"] == nil:
					hits = append(hits, Hit{Path: p, Msg: "Numeric input with no maximum accepts arbitrarily large values."})
				}
			})
			if len(hits) > 3 {
				hits = append(hits[:3], Hit{Path: hits[3].Path, Msg: fmt.Sprintf("And %d more unbounded inputs in this operation.", len(hits)-3)})
			}
			return hits
		}},
	{ID: "TG-OAS-009", Title: "Request body accepts undeclared properties", Severity: Low, Category: CatSecurity, CWE: "CWE-915", Types: oasOpT,
		Remediation: "Set additionalProperties: false on request objects so unexpected fields (mass assignment) are rejected.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			oasInputs(r, func(p string, s map[string]any) {
				if !strings.HasPrefix(p, "requestBody") {
					return
				}
				if t, _ := asString(s["type"]); t == "object" && s["properties"] != nil && s["additionalProperties"] == nil {
					hits = append(hits, Hit{Path: p, Msg: "The object accepts any extra field, which can reach the data layer unchecked."})
				}
			})
			return hits
		}},
	{ID: "TG-OAS-010", Title: "No security is defined for the API", Severity: Medium, Category: CatSecurity, CWE: "CWE-306", Types: oasDocT,
		Remediation: "Define at least one security scheme and a global security requirement.",
		Check: func(r *Resource) []Hit {
			if len(oasSchemes(r)) == 0 && r.Attrs["security"] == nil {
				return []Hit{{Path: "", Msg: "The document declares no authentication at all."}}
			}
			return nil
		}},
}

func oasLocal(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".local") || strings.Contains(host, "{")
}

func oasSchemePath(r *Resource, name string) string {
	if _, ok := r.Attrs["securityDefinitions"]; ok {
		return "securityDefinitions." + name
	}
	return "components.securitySchemes." + name
}
