package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

// secretRules find credentials in the raw text of every scanned file, of any
// format. Precision comes first: a pattern fires only on a known token shape
// or, for generic assignments, on a long, high-entropy value that is not a
// placeholder. Messages show at most the first 4 characters of a value.
var secretRules = []Rule{
	{ID: "TG-SECRET-001", Title: "AWS access key pair committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Deactivate the key in IAM now, remove it from git history, and use OIDC, an instance role or a secrets manager instead."},
	{ID: "TG-SECRET-002", Title: "GitHub token committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Revoke the token in GitHub settings, remove it from git history, and use GITHUB_TOKEN or a GitHub App in CI."},
	{ID: "TG-SECRET-003", Title: "GitLab token committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Revoke the token in GitLab, remove it from git history, and store it as a masked CI/CD variable."},
	{ID: "TG-SECRET-004", Title: "Slack token committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Revoke the token in the Slack app settings, remove it from git history, and read it from a secrets manager."},
	{ID: "TG-SECRET-005", Title: "Slack webhook URL committed", Severity: High, Category: CatSecurity, CWE: "CWE-798", Remediation: "Regenerate the webhook in Slack, remove it from git history, and pass it in as a secret variable."},
	{ID: "TG-SECRET-006", Title: "Stripe live key committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Roll the key in the Stripe dashboard, remove it from git history, and read it from a secrets manager."},
	{ID: "TG-SECRET-007", Title: "Google API key committed", Severity: High, Category: CatSecurity, CWE: "CWE-798", Remediation: "Delete or restrict the key in the Google Cloud console, remove it from git history, and read it from Secret Manager."},
	{ID: "TG-SECRET-008", Title: "Google service account key committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Delete the key in IAM, remove the file from git history, and use workload identity federation instead of key files."},
	{ID: "TG-SECRET-009", Title: "Azure storage or service account key committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Rotate the account key in Azure, remove it from git history, and use managed identity or Key Vault references."},
	{ID: "TG-SECRET-010", Title: "Azure SAS token committed", Severity: High, Category: CatSecurity, CWE: "CWE-798", Remediation: "Revoke the SAS (rotate the signing key or delete the stored access policy), remove it from git history, and issue short-lived SAS at runtime."},
	{ID: "TG-SECRET-011", Title: "Private key committed", Severity: Critical, Category: CatSecurity, CWE: "CWE-798", Remediation: "Treat the key as compromised: replace it, remove it from git history, and keep keys in a secrets manager or generate them at deploy time."},
	{ID: "TG-SECRET-012", Title: "JSON Web Token committed", Severity: High, Category: CatSecurity, CWE: "CWE-798", Remediation: "Revoke the token or rotate its signing key, remove it from git history, and fetch tokens at runtime."},
	{ID: "TG-SECRET-013", Title: "Nutanix Prism credential committed", Severity: High, Category: CatSecurity, CWE: "CWE-798", Remediation: "Change the Prism password, remove it from git history, and pass it in with NUTANIX_PASSWORD or a sensitive variable."},
	{ID: "TG-SECRET-014", Title: "Hardcoded password or secret value", Severity: High, Category: CatSecurity, CWE: "CWE-798", Remediation: "Rotate the value, remove it from git history, and read it from a secrets manager, a sensitive variable or a CI secret."},
	{ID: "TG-SECRET-015", Title: "Secret-bearing file committed", Severity: High, Category: CatSecurity, CWE: "CWE-312", Remediation: "Remove the file from git history, rotate what it holds, and add its name to .gitignore."},
}

type secretPattern struct {
	id, name string
	re       *regexp.Regexp
	group    int // capture group holding the secret; 0 means the whole match
}

// Ordered: specific shapes first, so a line reports its most specific secret once.
var secretPatterns = []secretPattern{
	{"TG-SECRET-008", "Google service account private key", regexp.MustCompile(`"private_key"\s*:\s*"(-----BEGIN (?:RSA )?PRIVATE KEY-----\\n[A-Za-z0-9+/=]{40,})`), 1},
	{"TG-SECRET-002", "GitHub token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`), 0},
	{"TG-SECRET-003", "GitLab token", regexp.MustCompile(`\b(?:glpat|gldt|glrt|glptt|glsoat)-[0-9A-Za-z_-]{20,}`), 0},
	{"TG-SECRET-005", "Slack webhook URL", regexp.MustCompile(`hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/([A-Za-z0-9]{20,})`), 1},
	{"TG-SECRET-004", "Slack token", regexp.MustCompile(`\bxox[abposr]-[0-9]{6,}-[0-9A-Za-z-]{10,}`), 0},
	{"TG-SECRET-006", "Stripe live key", regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,99}\b`), 0},
	{"TG-SECRET-007", "Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}(?:[^0-9A-Za-z_-]|$)`), 0},
	{"TG-SECRET-009", "Azure account key", regexp.MustCompile(`(?i)\b(?:AccountKey|SharedAccessKey)=([A-Za-z0-9+/]{40,}={0,2})`), 1},
	{"TG-SECRET-010", "Azure SAS token", regexp.MustCompile(`\bsv=\d{4}-\d{2}-\d{2}&.*?\bsig=([A-Za-z0-9%+/]{40,})`), 1},
	{"TG-SECRET-012", "JSON Web Token", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,})\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}`), 0},
}

var (
	awsKeyIDRE   = regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`)
	awsSecretRE  = regexp.MustCompile(`(?i)secret[A-Za-z0-9_-]*["']?\s*(?::|=|=>)\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)`)
	awsBareRE    = regexp.MustCompile(`^[\s,:|"';=]+([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)`)
	pemHeaderRE  = regexp.MustCompile(`-----BEGIN ((?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY( BLOCK)?-----`)
	pemBodyRE    = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)
	nutanixRE    = regexp.MustCompile(`(?i)^\s*provider\s+"nutanix"`)
	nutanixKeyRE = regexp.MustCompile(`(?i)(nutanix|prism)`)
	// A key ending in a secret word, then = or :, then a quoted or bare value.
	assignRE      = regexp.MustCompile(`(?i)(?:^|[\s"'{,(-])([A-Za-z0-9_.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key))["']?\s*(?::=|=>|:|=)\s*(?:"([^"]*)"|'([^']*)'|([^\s"'#,;]+))`)
	placeholderRE = regexp.MustCompile(`(?i)(example|changeme|change[_-]me|dummy|test|xxx|placeholder|sample|fake|your|redacted|password|secret|todo|replace|insert|default|foo|bar|qwerty|letmein|admin|12345|abcdef|\*\*\*|\.\.\.)`)
	templatedRE   = regexp.MustCompile(`\$\{|\{\{|\$\(|%\(|<[^>]*>|\$[A-Za-z_]|^\{|^!|^&|^\*|^arn:|^https?://|^/|(?i)^(var|local|data|module|each|self|count|path|terraform)\.`)
	dottedRefRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z0-9_\[\]-]+)+$`)
	identRE       = regexp.MustCompile(`^([A-Z0-9_]+|[a-z_-]+|[a-z]+([A-Z][a-z]+)+)$`)
	uuidRE        = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	commentRE     = regexp.MustCompile(`^\s*(#|//|\*|/\*|<!--|;|REM\b|::)`)
)

// Documented sample values from vendor docs: never reported.
var knownFakes = []string{
	"EXAMPLE", // AWS key IDs and EXAMPLEKEY secrets
	"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IF", // Azurite development storage key
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",    // jwt.io sample signature
}

func isKnownFake(v string) bool {
	for _, k := range knownFakes {
		if strings.Contains(v, k) {
			return true
		}
	}
	return false
}

// redact shows at most the first 4 characters of a secret.
func redact(v string) string {
	r := []rune(v)
	return string(r[:min(4, len(r)/4)]) + "..."
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	n := map[rune]float64{}
	for _, c := range s {
		n[c]++
	}
	l := float64(len([]rune(s)))
	e := 0.0
	for _, c := range n {
		p := c / l
		e -= p * math.Log2(p)
	}
	return e
}

func charClasses(s string) int {
	var lo, up, dg, sy bool
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= '0' && c <= '9':
			dg = true
		default:
			sy = true
		}
	}
	n := 0
	for _, b := range []bool{lo, up, dg, sy} {
		if b {
			n++
		}
	}
	return n
}

// placeholder reports values that are obviously not real secrets, also after base64 decoding.
func placeholder(v string) bool {
	if templatedRE.MatchString(v) || placeholderRE.MatchString(v) {
		return true
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && placeholderRE.Match(b) {
		return true
	}
	return false
}

// genericSecret is the value gate for `password = "..."` style assignments.
func genericSecret(v string) bool {
	n := len([]rune(v))
	return n >= 12 && n <= 200 && !placeholder(v) && !dottedRefRE.MatchString(v) && !identRE.MatchString(v) &&
		!uuidRE.MatchString(v) && charClasses(v) >= 2 && entropy(v) >= 3.5 && !isKnownFake(v)
}

// IsSecretFileName reports a file whose name says it holds credentials. The
// CLI passes such files by name only and never reads their content.
func IsSecretFileName(name string) bool {
	base := strings.ToLower(path.Base(name))
	switch base {
	case ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials.json", "kubeconfig":
		return true
	}
	if rest, ok := strings.CutPrefix(base, ".env."); ok {
		// Templates are meant to be committed.
		return !strings.Contains(rest, "example") && !strings.Contains(rest, "sample") && !strings.Contains(rest, "template") &&
			!strings.Contains(rest, "dist") && !strings.Contains(rest, "defaults")
	}
	if strings.HasSuffix(base, ".pem") {
		// Certificates and public keys are not secrets.
		for _, pub := range []string{"cert", "chain", "ca.", "ca-", "ca_", "pub", "bundle"} {
			if strings.Contains(base, pub) {
				return false
			}
		}
		return true
	}
	return strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".pfx") || strings.HasSuffix(base, ".p12")
}

// secretScan reports TG-SECRET-* findings for every file in files.
func secretScan(files map[string]string) []Finding {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Finding
	for _, name := range names {
		if IsSecretFileName(name) {
			out = append(out, newFinding("TG-SECRET-015", "", path.Base(name)+" is part of the scanned files. Files with this name hold credentials or private keys.", "", name, 0))
			continue
		}
		if strings.Contains(name, ".tfstate") || path.Base(name) == ".terraform.lock.hcl" {
			continue // state is TG-STATE-002; lock files hold only hashes
		}
		out = append(out, secretsInFile(name, files[name])...)
	}
	return out
}

func secretsInFile(name, src string) []Finding {
	var out []Finding
	lines := strings.Split(src, "\n")
	hcl := isHCLFile(name)
	inNutanix := false
	add := func(id, msg string, line int) {
		out = append(out, newFinding(id, "", msg, "", name, line))
	}
	for i, line := range lines {
		if len(line) > 4096 {
			line = line[:4096] // minified files: bound the regex work
		}
		if hcl && nutanixRE.MatchString(line) {
			inNutanix = true
		} else if inNutanix && strings.HasPrefix(line, "}") {
			inNutanix = false
		}
		if id, msg := lineSecret(lines, i, line, hcl, inNutanix); id != "" {
			add(id, msg, i+1)
		}
	}
	return out
}

// lineSecret returns the most specific secret on one line.
func lineSecret(lines []string, i int, line string, hcl, inNutanix bool) (string, string) {
	if m := awsKeyIDRE.FindStringSubmatchIndex(line); m != nil {
		id := line[m[2]:m[3]]
		if sec := awsPairSecret(lines, i, line[m[3]:]); sec != "" && !isKnownFake(id) && !isKnownFake(sec) {
			return "TG-SECRET-001", fmt.Sprintf("AWS access key (%s) with its secret access key (%s) is committed.", redact(id), redact(sec))
		}
	}
	for _, p := range secretPatterns {
		m := p.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v := strings.TrimRight(m[p.group], " \t\"',;)")
		body := v
		if j := strings.LastIndexAny(v, "_-"); j > 0 && p.id != "TG-SECRET-012" && p.id != "TG-SECRET-008" {
			body = v[j+1:] // the random part after the token prefix
		}
		if isKnownFake(line) || entropy(body) < 3.0 {
			continue
		}
		if p.id == "TG-SECRET-012" && !jwtHeader(m[1]) {
			continue
		}
		return p.id, fmt.Sprintf("%s (%s) is committed.", p.name, redact(v))
	}
	if m := pemHeaderRE.FindStringIndex(line); m != nil && !isKnownFake(line) {
		rest := strings.TrimPrefix(line[m[1]:], `\n`)
		if !pemBodyRE.MatchString(rest) {
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if t := strings.TrimSpace(lines[j]); t != "" {
					rest = t
					break
				}
			}
		}
		if b := pemBodyRE.FindString(rest); b != "" && entropy(b) >= 4.0 {
			return "TG-SECRET-011", "A private key (" + strings.TrimSpace(line[m[0]:m[1]]) + ") is committed."
		}
	}
	if commentRE.MatchString(line) {
		return "", ""
	}
	for _, m := range assignRE.FindAllStringSubmatch(line, -1) {
		key, v, quoted := m[1], m[2]+m[3], m[2] != "" || m[3] != ""
		if !quoted {
			v = m[4]
			if hcl {
				continue // a bare value in HCL is an expression, not a literal
			}
		}
		if secretMetaRE.MatchString(strings.ReplaceAll(strings.ToLower(key), "-", "_")) {
			continue
		}
		nutanix := inNutanix || nutanixKeyRE.MatchString(key)
		lk := strings.ToLower(key)
		if nutanix && (strings.HasSuffix(lk, "password") || strings.HasSuffix(lk, "passwd") || strings.HasSuffix(lk, "pwd")) {
			// The documented factory default is a finding too; anything else passes the generic gate.
			if strings.EqualFold(v, "nutanix/4u") || genericSecret(v) {
				return "TG-SECRET-013", fmt.Sprintf("%q sets the Nutanix Prism password (%s).", key, redact(v))
			}
			continue
		}
		if genericSecret(v) {
			return "TG-SECRET-014", fmt.Sprintf("%q is set to a literal value (%s).", key, redact(v))
		}
	}
	return "", ""
}

// awsPairSecret finds a secret access key next to a key ID: on the same line
// after it, or in a secret-named assignment within 4 lines.
func awsPairSecret(lines []string, i int, after string) string {
	ok := func(s string) bool { return charClasses(s) >= 3 && entropy(s) >= 4.0 }
	if m := awsBareRE.FindStringSubmatch(after); m != nil && ok(m[1]) {
		return m[1]
	}
	for j := max(0, i-4); j < len(lines) && j <= i+4; j++ {
		if m := awsSecretRE.FindStringSubmatch(lines[j]); m != nil && ok(m[1]) {
			return m[1]
		}
	}
	return ""
}

// jwtHeader reports whether the first JWT segment decodes to a JSON header with alg.
func jwtHeader(seg string) bool {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return false
	}
	var h map[string]any
	if json.Unmarshal(b, &h) != nil {
		return false
	}
	alg, _ := h["alg"].(string)
	return alg != "" && !strings.EqualFold(alg, "none")
}

// supersedeOldSecrets keeps one finding per secret: a specific token rule
// replaces TG-SEC-001 and TG-SEC-002 (the older pattern list) on the same
// line, and the generic TG-SECRET-014 yields to TG-SEC-001, which reports the
// same assignment (matched by line, or by key name when it has no line).
func supersedeOldSecrets(fs []Finding) []Finding {
	at := func(f Finding) string { return fmt.Sprintf("%s:%d", f.File, f.Line) }
	named := func(f Finding) string { k, _, _ := strings.Cut(f.Message, " is set"); return f.File + "|" + k }
	specific, sec001 := map[string]bool{}, map[string]bool{}
	for _, f := range fs {
		switch {
		case f.RuleID == "TG-SEC-001":
			sec001[at(f)], sec001[named(f)] = true, true
		case strings.HasPrefix(f.RuleID, "TG-SECRET-") && f.RuleID != "TG-SECRET-014":
			specific[at(f)] = true
		}
	}
	out := fs[:0]
	for _, f := range fs {
		if ((f.RuleID == "TG-SEC-001" || f.RuleID == "TG-SEC-002") && specific[at(f)]) ||
			(f.RuleID == "TG-SECRET-014" && (sec001[at(f)] || sec001[named(f)])) {
			continue
		}
		out = append(out, f)
	}
	return out
}
