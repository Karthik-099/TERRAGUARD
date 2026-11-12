package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// Test tokens are assembled at run time so no credential-shaped literal sits
// in the source. Failure messages never print a token.
const rnd = "a8Kq2Zp9Lm4Xr7Tb1Vn6Yc3Wd5Hs0Jf8Ge2Qu4Mi7Ok9Pl3Rv6Sx1Ty5Uz0WaBcDeFgHiJkLmNoPqRsTuVwXyZ"

func tok(prefix string, n int) string { return prefix + rnd[:n] }

func secretIDs(t *testing.T, name, src string) map[string]Finding {
	t.Helper()
	got := map[string]Finding{}
	for _, f := range Scan(Input{Files: map[string]string{name: src}}).Findings {
		if strings.HasPrefix(f.RuleID, "TG-SECRET-") || strings.HasPrefix(f.RuleID, "TG-SEC-") {
			got[f.RuleID] = f
		}
	}
	return got
}

func TestSecretPatterns(t *testing.T) {
	akid := "AK" + "IA" + "Z7QW3RT5YU8IOP2L"
	awsSecret := "k9Jd/3mQ+Zr8" + rnd[:28]
	jwtHead := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}
	cases := []struct {
		id, name, src, secret string
	}{
		{"TG-SECRET-001", "creds.yaml", "aws_access_key_id: " + akid + "\naws_secret_access_key: " + awsSecret + "\n", akid},
		{"TG-SECRET-001", "keys.csv.yaml", "key: " + akid + "," + awsSecret + "\n", akid},
		{"TG-SECRET-002", ".github/workflows/ci.yml", "env:\n  TOKEN_X: " + tok("gh"+"p_", 36) + "\n", tok("gh"+"p_", 36)},
		{"TG-SECRET-003", "ci.yaml", "token_value: " + tok("gl"+"pat-", 20) + "\n", tok("gl"+"pat-", 20)},
		{"TG-SECRET-004", "app.json", `{"slack": "` + "xo" + "xb-1234567890-" + rnd[:24] + `"}`, "xo" + "xb-1234567890-" + rnd[:24]},
		{"TG-SECRET-005", "notify.tf", `variable "x" { default = "https://hooks.slack.com/services/T0ABCDEF1/B0ABCDEF2/` + rnd[:24] + `" }`, rnd[:24]},
		{"TG-SECRET-006", "Dockerfile", "FROM alpine:3.19\nENV STRIPE=" + tok("sk"+"_live_", 24) + "\n", tok("sk"+"_live_", 24)},
		{"TG-SECRET-007", "web.yaml", "maps: " + "AI" + "za" + "Sy" + rnd[:33] + "\n", "AI" + "za" + "Sy" + rnd[:33]},
		{"TG-SECRET-008", "sa.json", `{"type": "service_account", "private_key": "-----BEGIN ` + "PRIVATE KEY-----\\n" + rnd[:64] + "\\n-----END " + `PRIVATE KEY-----\n"}`, rnd[:64]},
		{"TG-SECRET-009", "app.yaml", "conn: DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + rnd[:86] + "==;EndpointSuffix=core.windows.net\n", rnd[:86]},
		{"TG-SECRET-010", "blob.yaml", "url: https://acct.blob.core.windows.net/c?sv=2022-11-02&ss=b&srt=o&sp=r&se=2030-01-01&sig=" + rnd[:44] + "%3D\n", rnd[:44]},
		{"TG-SECRET-011", "tls.tf", "locals {\n  key = <<EOT\n-----BEGIN RSA " + "PRIVATE KEY-----\n" + rnd[:64] + "\n-----END RSA PRIVATE KEY-----\nEOT\n}\n", rnd[:64]},
		{"TG-SECRET-012", "client.yaml", "auth: " + jwtHead + ".eyJzdWIiOiJhYmMxMjMiLCJpYXQiOjE3MDAwMDAwMDB9." + rnd[:43] + "\n", rnd[:43]},
		{"TG-SECRET-013", "nutanix.tf", "provider \"nutanix\" {\n  username = \"admin\"\n  password = \"Nutanix/4u\"\n}\n", "Nutanix/4u"},
		{"TG-SECRET-013", "inventory.yml", "nutanix_password: Pr1sm-" + rnd[:10] + "\n", "Pr1sm-" + rnd[:10]},
		{"TG-SECRET-014", "values.yaml", "db:\n  password: " + rnd[:20] + "\n", rnd[:20]},
		{"TG-SECRET-014", "main.tf", "locals {\n  client_secret = \"" + rnd[3:23] + "\"\n}\n", rnd[3:23]},
		{"TG-SECRET-014", "deploy.yml", "steps:\n  - run: deploy --x\n    env:\n      API_KEY: " + rnd[5:25] + "\n", rnd[5:25]},
	}
	for _, c := range cases {
		got := secretIDs(t, c.name, c.src)
		f, ok := got[c.id]
		if !ok {
			ids := []string{}
			for id := range got {
				ids = append(ids, id)
			}
			t.Errorf("%s in %s: not reported (got %v)", c.id, c.name, ids)
			continue
		}
		if strings.Contains(f.Message, c.secret) || strings.Contains(f.Message, c.secret[4:]) {
			t.Errorf("%s in %s: the message holds the secret unredacted", c.id, c.name)
		}
		if f.Line == 0 || f.Fix != nil {
			t.Errorf("%s in %s: want a line and no fix", c.id, c.name)
		}
		if got["TG-SEC-002"].RuleID != "" && got["TG-SEC-002"].Line == f.Line {
			t.Errorf("%s in %s: TG-SEC-002 duplicates it on the same line", c.id, c.name)
		}
	}
}

func TestSecretNegatives(t *testing.T) {
	cases := map[string]string{
		"aws-docs.tf":   "provider \"aws\" {\n  access_key = \"" + "AKIA" + "IOSFODNN7EXAMPLE" + "\"\n  secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY\"\n}\n",
		"lone-key.yaml": "id: " + "AKIA" + "Z7QW3RT5YU8IOP2L" + "\n", // no adjacent secret: TG-SEC-002 still reports it
		"vars.tf":       "resource \"x\" \"y\" {\n  password = var.db_password\n  token = local.t\n  secret = \"${var.s}\"\n}\n",
		"values.yaml": "password: changeme\npassword: \"{{ vault_db_password }}\"\npassword: ${DB_PASSWORD}\napi_key: <your-api-key>\n" +
			"token: xxxxxxxxxxxxxxxxxxxx\npassword: !Ref DbPassword\nsecret: arn:aws:secretsmanager:us-east-1:1:secret:x\n" +
			"client_secret: DB_CLIENT_SECRET_NAME\ntoken: short\npassword: example-Pass-1234\nsecretName: my-k8s-secret-name\n" +
			"secretKeyRef: abcdefghijklmnop\napi_key: 123e4567-e89b-12d3-a456-426614174000\npassword: dGVzdHBhc3N3b3JkMTIz\n",
		"comment.tf":  "# password = \"" + rnd[:20] + "\"\n",
		"ci.yml":      "env:\n  GH_TOKEN: ${{ secrets.GH_TOKEN }}\n  T: " + "gh" + "p_" + strings.Repeat("x", 36) + "\n",
		"jwt.yaml":    "t: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n",
		"pem.tf":      "# -----BEGIN " + "PRIVATE KEY-----\n# ...\n",
		"azurite.yml": "c: AccountKey=" + "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==\n",
		"nutanix.tf":  "provider \"nutanix\" {\n  password = var.nutanix_password\n}\n",
	}
	for name, src := range cases {
		for id := range secretIDs(t, name, src) {
			if strings.HasPrefix(id, "TG-SECRET-") {
				t.Errorf("%s: unexpected %s", name, id)
			}
		}
	}
}

func TestSecretInlineIgnoreAndOutputs(t *testing.T) {
	secret := rnd[:24]
	src := "db:\n  # terraguard:ignore TG-SECRET-014\n  password: " + secret + "\n  api_key: " + rnd[30:54] + "\n"
	rep := Scan(Input{Files: map[string]string{"values.yaml": src}})
	waived, active := 0, 0
	for _, f := range rep.Findings {
		if f.RuleID == "TG-SECRET-014" {
			if f.Waived {
				waived++
			} else {
				active++
			}
		}
	}
	if waived != 1 || active != 1 {
		t.Fatalf("want one waived and one active TG-SECRET-014, got %d and %d", waived, active)
	}
	js, _ := json.Marshal(rep)
	sarif, _ := SARIF(rep)
	for name, out := range map[string]string{"json": string(js), "sarif": string(sarif), "markdown": Markdown(rep), "text": Text(rep)} {
		if strings.Contains(out, secret) || strings.Contains(out, rnd[30:54]) || strings.Contains(out, secret[4:12]) {
			t.Errorf("%s output holds a secret value", name)
		}
	}
}

func TestSecretFileNames(t *testing.T) {
	for name, want := range map[string]bool{
		".env": true, "app/.env.production": true, ".env.example": false, ".env.sample": false, "certs/server.key": true,
		"tls/server.pem": true, "tls/cert.pem": false, "tls/ca.pem": false, "home/id_rsa": true, "id_ed25519": true,
		"id_rsa.pub": false, "store.pfx": true, "store.p12": true, "gcp/credentials.json": true, "kubeconfig": true, "main.tf": false,
	} {
		if IsSecretFileName(name) != want {
			t.Errorf("IsSecretFileName(%q) = %v", name, !want)
		}
	}
	rep := Scan(Input{Files: map[string]string{"main.tf": "", "deploy/.env": "", ".env.example": ""}})
	n := 0
	for _, f := range rep.Findings {
		if f.RuleID == "TG-SECRET-015" {
			n++
			if f.File != "deploy/.env" {
				t.Errorf("TG-SECRET-015 on %s", f.File)
			}
		}
	}
	if n != 1 {
		t.Errorf("want one TG-SECRET-015, got %d", n)
	}
}

func TestSecretRulesCatalogued(t *testing.T) {
	for _, r := range secretRules {
		if ruleIndex[r.ID] == nil || RuleSince(r.ID) != "3.0" || len(ThemesFor(r.ID)) == 0 {
			t.Errorf("%s: missing from the index, versions or themes", r.ID)
		}
	}
}

func TestRedact(t *testing.T) {
	for _, v := range []string{"abcdefghijklmnopqrstuvwxyz", "abcdefgh", "ab", ""} {
		r := redact(v)
		if !strings.HasSuffix(r, "...") || len(r) > 7 || (len(v) > 3 && strings.Contains(r, v)) {
			t.Errorf("redact of a %d-character value shows too much", len(v))
		}
	}
}
