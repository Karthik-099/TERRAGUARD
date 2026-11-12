package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCodeOwnersSemantics(t *testing.T) {
	co := ParseCodeOwners(`# comment
*                 @org/everyone
*.tf              @org/terraform
/build/logs/      @org/build
docs/*            docs@example.com
apps/             @org/apps
**/k8s            @org/platform
/modules/**/net   @org/network
/infra/legacy/
\#hash            @org/hash
`)
	for file, want := range map[string]string{
		"README.md":                    "@org/everyone",
		"main.tf":                      "@org/terraform",
		"modules/vpc/main.tf":          "@org/terraform",
		"build/logs/x.log":             "@org/build",
		"sub/build/logs/x.log":         "@org/everyone", // anchored
		"docs/guide.md":                "docs@example.com",
		"docs/deep/guide.md":           "@org/everyone", // docs/* is not recursive
		"apps/web/Dockerfile":          "@org/apps",
		"src/apps/web/Dockerfile":      "@org/apps", // apps/ matches at any depth
		"deploy/k8s/svc.yaml":          "@org/platform",
		"k8s/svc.yaml":                 "@org/platform",
		"modules/a/b/net/x.yaml":       "@org/network",
		"infra/legacy/main.tf":         "", // no owners clears them
		"#hash":                        "@org/hash",
		"apps.yaml":                    "@org/everyone",
		"modules/a/b/net/variables.tf": "@org/network", // the later line wins over *.tf
	} {
		if got := strings.Join(co.Owners(file), " "); got != want {
			t.Errorf("Owners(%q) = %q, want %q", file, got, want)
		}
	}
	if got := co.OwnersUnder("repo", "repo/main.tf"); len(got) != 1 || got[0] != "@org/terraform" {
		t.Errorf("OwnersUnder with a root = %v", got)
	}
	if got := co.OwnersUnder("repo", "other/main.tf"); got != nil {
		t.Errorf("a file outside the root got owners %v", got)
	}
}

func TestScanSetsCodeOwners(t *testing.T) {
	in := Input{
		Files:          map[string]string{"infra/net/main.tf": `resource "aws_s3_bucket" "b" { bucket = "x-logs-1" }`, "infra/app/values.yaml": "password: " + rnd[:20] + "\n"},
		CodeOwners:     "/net/ @org/network\n",
		CodeOwnersRoot: "infra",
	}
	rep := Scan(in)
	owned, unowned := 0, 0
	for _, f := range rep.Findings {
		switch {
		case f.File == "":
		case strings.HasPrefix(f.File, "infra/net/") && len(f.CodeOwners) == 1 && f.CodeOwners[0] == "@org/network":
			owned++
		case strings.HasPrefix(f.File, "infra/app/") && len(f.CodeOwners) == 0:
			unowned++
		default:
			t.Errorf("%s on %s has owners %v", f.RuleID, f.File, f.CodeOwners)
		}
	}
	if owned == 0 || unowned == 0 {
		t.Fatalf("want owned and unowned findings, got %d and %d", owned, unowned)
	}
	groups := GroupByOwner(rep.Findings)
	if len(groups) != 2 || groups[0].Owner != "@org/network" || groups[1].Owner != Unowned {
		t.Errorf("groups: %+v", groups)
	}
	if !strings.Contains(TextByOwner(rep), "== @org/network: ") || !strings.Contains(MarkdownByOwner(rep), "### unowned (") {
		t.Error("grouped output is missing a section")
	}
	if !strings.Contains(Markdown(rep), "| Owners |") {
		t.Error("markdown has no owners column")
	}
	sarif, _ := SARIF(rep)
	if !strings.Contains(string(sarif), `"code_owners"`) {
		t.Error("SARIF has no code_owners property")
	}
	var back Input
	if err := json.Unmarshal([]byte(`{"files":{},"code_owners":"* @a","code_owners_root":"x"}`), &back); err != nil || back.CodeOwners != "* @a" || back.CodeOwnersRoot != "x" {
		t.Errorf("JSON input does not reach CodeOwners: %+v", back)
	}
}
