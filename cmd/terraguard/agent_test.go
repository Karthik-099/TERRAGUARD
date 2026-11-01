package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const openSSH = `resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`

func runAgentWith(t *testing.T, reply string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":` + reply + `}}]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TERRAGUARD_AI_BASE_URL", srv.URL)
	t.Setenv("TERRAGUARD_AI_ROUTE", "custom:fake")
	t.Setenv("TERRAGUARD_AI_LOCAL_ONLY", "")
	t.Chdir(t.TempDir())
	os.WriteFile("main.tf", []byte(openSSH), 0o644)
	if err := runAgent([]string{"--write", "--rounds", "1", "."}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile("main.tf")
	return string(b)
}

func TestAgentKeepsVerifiedFix(t *testing.T) {
	fixed := strings.Replace(openSSH, "0.0.0.0/0", "10.0.0.0/8", 1)
	got := runAgentWith(t, jsonString("```hcl\n"+fixed+"```"))
	if !strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("verified fix was not written:\n%s", got)
	}
}

func TestAgentRejectsWorseProposal(t *testing.T) {
	worse := strings.Replace(openSSH, `from_port   = 22`, `from_port   = 0`, 1) // widens to all ports
	got := runAgentWith(t, jsonString("```hcl\n"+strings.Replace(worse, `to_port     = 22`, `to_port     = 65535`, 1)+"```"))
	if !strings.Contains(got, "from_port   = 22") {
		t.Fatalf("a worse proposal must be rejected:\n%s", got)
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
