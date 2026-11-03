package engine

import (
	"strings"
	"testing"
)

func TestParseDockerfile(t *testing.T) {
	src := "# syntax=docker/dockerfile:1\n# escape=\\\nARG V=1\nFROM alpine:3 AS base\nRUN apk add \\\n  # a comment inside\n  curl\nRUN <<EOF\necho hi\nEOF\nENV A=1 B=\"two words\"\nENV C three words\nUSER app\nFROM base\nCMD [\"run\"]\n"
	rs, syntax := parseDockerfile("Dockerfile", src)
	if len(syntax) != 0 || len(rs) != 3 {
		t.Fatalf("resources %d, syntax %v", len(rs), syntax)
	}
	file, base, final := rs[0], rs[1], rs[2]
	if base.Address != "dockerfile_stage.base" || final.Name != "stage1" || file.Type != "dockerfile" {
		t.Fatalf("names: %s %s %s", file.Address, base.Address, final.Address)
	}
	ins := dkInstrs(base.Attrs)
	if ins[1].value != "apk add curl" || base.Lines["instructions.1"] != 5 {
		t.Errorf("continuation: %q line %d", ins[1].value, base.Lines["instructions.1"])
	}
	if !strings.Contains(ins[2].value, "echo hi") {
		t.Errorf("heredoc body missing: %q", ins[2].value)
	}
	env := base.Attrs["env"].(map[string]any)
	if env["B"] != "two words" || env["C"] != "three words" {
		t.Errorf("env: %v", env)
	}
	if p, _ := asFloat(final.Attrs["parent"]); p != 0 || base.Attrs["shipped"] != true || final.Attrs["final"] != true {
		t.Errorf("stage chain: %v", final.Attrs)
	}
	if d := dkInstrs(final.Attrs)[1]; !d.json || d.args[0] != "run" {
		t.Errorf("exec form: %+v", d)
	}
	if _, ok := file.Attrs["args"].(map[string]any)["V"]; !ok {
		t.Error("global ARG missing")
	}
	if _, bad := parseDockerfile("Dockerfile", "FROM a\nRUNN x\n"); len(bad) != 1 || bad[0].Line != 2 {
		t.Errorf("unknown instruction: %v", bad)
	}
	if _, bad := parseDockerfile("Dockerfile", "ENV A=1\n"); len(bad) != 1 {
		t.Errorf("missing FROM: %v", bad)
	}
}

func TestDockerHelpers(t *testing.T) {
	for img, want := range map[string]string{"alpine": "latest", "alpine:latest": "latest", "reg:5000/a": "latest",
		"reg:5000/a:1.2": "tag", "a@sha256:00": "digest", "$BASE": "var"} {
		if got := imageRef(img); got != want {
			t.Errorf("imageRef(%q) = %s, want %s", img, got, want)
		}
	}
	p, ok := dkInstall(dockerWords("DEBIAN_FRONTEND=noninteractive sudo apt-get -qq install -o Dpkg::Options::=x curl=7 git"))
	if !ok || p.mgr != "apt-get" || len(p.pkgs) != 2 || !dkAssumeYes(p) || dkPinned(p, "git") || !dkPinned(p, "curl=7") {
		t.Errorf("dkInstall: %+v", p)
	}
	if !dkHasPipe(`curl x | sh`) || dkHasPipe(`grep "a|b" f || true`) {
		t.Error("dkHasPipe")
	}
	if !pipeShellRE.MatchString(`sh -c "$(curl -fsSL https://x)"`) || pipeShellRE.MatchString(`curl -o x https://x && sh x`) {
		t.Error("pipeShellRE")
	}
}

// Every registered Dockerfile, compose and CI rule is unique, and every mapped reference ID points at one.
func TestDockerCIRuleRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] && (strings.HasPrefix(r.ID, "TG-DOCKER-") || strings.HasPrefix(r.ID, "TG-COMPOSE-") || strings.HasPrefix(r.ID, "TG-GHA-")) {
			t.Errorf("duplicate rule %s", r.ID)
		}
		seen[r.ID] = true
	}
	for _, m := range []map[string][]string{dockerForeign, ciForeign} {
		for ref, ids := range m {
			for _, id := range ids {
				if ruleIndex[id] == nil {
					t.Errorf("%s maps to unknown rule %s", ref, id)
				}
			}
		}
	}
}
