package engine

import (
	"strings"
	"time"
)

// Cloudflare rules for both provider generations: v4 names (cloudflare_access_policy,
// cloudflare_tunnel_config, cloudflare_zone_settings_override) and v5 names
// (cloudflare_zero_trust_*, cloudflare_zone_setting).

var cfAccessPolicyT = []string{"cloudflare_access_policy", "cloudflare_zero_trust_access_policy"}

// cfZoneSetting returns a zone setting from either shape: v4 settings { k = v }
// or v5 one resource per setting (setting_id, value).
func cfZoneSetting(r *Resource, key string) (any, bool) {
	if r.Type == "cloudflare_zone_setting" {
		if id, _ := asString(r.get("setting_id")); id == key {
			return r.get("value"), true
		}
		return nil, false
	}
	v := r.get("settings." + key)
	return v, v != nil
}

var cloudflareRules = []Rule{
	{ID: "TG-CF-004", Title: "Access policy lets everyone in", Severity: High, Category: CatSecurity, CWE: "CWE-284", Types: cfAccessPolicyT,
		Remediation: "Include specific emails, email domains, groups or identity provider groups instead of everyone.",
		Check: func(r *Resource) []Hit {
			if d, _ := asString(r.get("decision")); d != "" && d != "allow" {
				return nil
			}
			for _, inc := range append(r.blocks("include"), cfIncludes(r)...) {
				if cfEveryone(inc["everyone"]) {
					return []Hit{{Path: "include", Msg: "Any person on the internet who completes the login step is allowed into the application."}}
				}
			}
			return nil
		}},
	{ID: "TG-CF-005", Title: "Access sessions last longer than a day", Severity: Low, Category: CatSecurity, CWE: "CWE-613",
		Types: []string{"cloudflare_access_application", "cloudflare_zero_trust_access_application"}, Remediation: `Set session_duration to "24h" or less.`,
		Check: func(r *Resource) []Hit {
			s, ok := asString(r.get("session_duration"))
			if !ok {
				return nil
			}
			if d, err := time.ParseDuration(s); err == nil && d > 24*time.Hour {
				return []Hit{{Path: "session_duration", Msg: "A stolen session cookie keeps working for " + s + "."}}
			}
			return nil
		}},
	{ID: "TG-CF-006", Title: "R2 bucket is served on the public r2.dev URL", Severity: Medium, Category: CatSecurity, CWE: "CWE-200",
		Types: []string{"cloudflare_r2_managed_domain"}, Remediation: "Set enabled = false and serve the bucket through a custom domain with Access or WAF in front, if it must be public.",
		Check: func(r *Resource) []Hit {
			if is(r.get("enabled"), true) {
				return []Hit{{Path: "enabled", Msg: "Every object in the bucket can be downloaded by anyone, with no WAF, caching rules or access control."}}
			}
			return nil
		}},
	{ID: "TG-CF-007", Title: "API token has no expiry and no IP restriction", Severity: Low, Category: CatSecurity, CWE: "CWE-324",
		Types: []string{"cloudflare_api_token", "cloudflare_account_token"}, Remediation: "Set expires_on, and limit the token with condition { request_ip { in = [...] } }.",
		Check: func(r *Resource) []Hit {
			if r.get("expires_on") != nil || r.get("condition") != nil {
				return nil
			}
			return []Hit{{Path: "", Msg: "A leaked token works from anywhere, for ever."}}
		}},
	{ID: "TG-CF-008", Title: "Zone security features are switched off", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"cloudflare_zone_settings_override", "cloudflare_zone_setting"}, Remediation: `Keep security_level at "medium" or higher, and browser_check and waf "on".`,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if v, ok := cfZoneSetting(r, "security_level"); ok {
				if s, _ := asString(v); s == "essentially_off" || s == "off" {
					hits = append(hits, Hit{Path: "settings", Msg: "security_level " + s + " lets known malicious visitors through without a challenge."})
				}
			}
			for _, k := range []string{"browser_check", "waf"} {
				if v, ok := cfZoneSetting(r, k); ok {
					if s, _ := asString(v); s == "off" {
						hits = append(hits, Hit{Path: "settings", Msg: k + " is off, so bad bots and common attacks reach the origin."})
					}
				}
			}
			return hits
		}},
	{ID: "TG-CF-009", Title: "Zone does not send HSTS", Severity: Low, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"cloudflare_zone_settings_override"}, Remediation: "Set security_header { enabled = true, max_age = 31536000, include_subdomains = true }.",
		Check: func(r *Resource) []Hit {
			if v := r.get("settings.security_header.enabled"); v != nil && is(v, false) {
				return []Hit{{Path: "settings", Msg: "Browsers can be downgraded to plain HTTP on the first visit."}}
			}
			return nil
		}},
	{ID: "TG-CF-010", Title: "Firewall rule skips security for every request", Severity: Medium, Category: CatSecurity, CWE: "CWE-693",
		Types: []string{"cloudflare_ruleset"}, Remediation: "Scope skip and allow rules to specific paths, hosts or source IP ranges.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, rule := range r.blocks("rules") {
				expr, _ := asString(rule["expression"])
				act, _ := asString(rule["action"])
				if (act == "skip" || act == "allow") && strings.TrimSpace(expr) == "true" && !is(rule["enabled"], false) {
					hits = append(hits, Hit{Path: "rules", Msg: "A " + act + " rule with the expression true turns the protection off for all traffic."})
				}
			}
			return hits
		}},
	{ID: "TG-CF-011", Title: "Tunnel does not verify the origin certificate", Severity: Medium, Category: CatSecurity, CWE: "CWE-295",
		Types: []string{"cloudflare_tunnel_config", "cloudflare_zero_trust_tunnel_cloudflared_config"}, Remediation: "Remove no_tls_verify and give the origin a certificate the tunnel can verify (origin_server_name, ca_pool).",
		Check: func(r *Resource) []Hit {
			if cfAnyTrue(r.Attrs, "no_tls_verify", 0) || cfAnyTrue(r.Attrs, "noTLSVerify", 0) {
				return []Hit{{Path: "config", Msg: "Traffic from the tunnel to the origin can be intercepted without detection."}}
			}
			return nil
		}},
}

// cfIncludes reads v5 include lists ([{ everyone = {} }]).
func cfIncludes(r *Resource) []map[string]any {
	var out []map[string]any
	if l, ok := r.get("include").([]any); ok {
		for _, e := range l {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// cfEveryone is v4's everyone = true or v5's everyone = {}.
func cfEveryone(v any) bool {
	_, isObject := v.(map[string]any)
	return is(v, true) || isObject
}

// cfAnyTrue finds key = true anywhere below v.
func cfAnyTrue(v any, key string, depth int) bool {
	if depth > 12 {
		return false
	}
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if k == key && is(e, true) || cfAnyTrue(e, key, depth+1) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if cfAnyTrue(e, key, depth+1) {
				return true
			}
		}
	}
	return false
}
