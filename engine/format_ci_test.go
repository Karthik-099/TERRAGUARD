package engine

import "testing"

func TestParseCI(t *testing.T) {
	rs, _ := parseGitHubActions(".github/workflows/ci.yml", "on: [push]\njobs:\n  b:\n    steps:\n      - run: |\n          one\n          two\n")
	if len(rs) != 2 || rs[1].Address != "github_job.b" || rs[1].Lines["steps.0.run@1"] != 7 {
		t.Fatalf("github: %d resources, lines %v", len(rs), rs[len(rs)-1].Lines)
	}
	if asStrings(rs[1].Attrs["triggers"])[0] != "push" {
		t.Errorf("triggers: %v", rs[1].Attrs["triggers"])
	}

	rs, _ = parseBitbucket("bitbucket-pipelines.yml", "pipelines:\n  default:\n    - step:\n        script: [a]\n  branches:\n    main:\n      - parallel:\n          steps:\n            - step:\n                name: Lint\n                script: [b]\n")
	if len(rs) != 3 || rs[1].Address != "bitbucket_step.Lint" || rs[2].Line != 3 {
		t.Fatalf("bitbucket: %+v", rs)
	}

	rs, _ = parseAzurePipelines("azure-pipelines.yml", "stages:\n  - stage: s\n    jobs:\n      - job: A\n      - deployment: D\n")
	if len(rs) != 3 || rs[1].Name != "A" || rs[2].Name != "D" || rs[2].Line != 5 {
		t.Fatalf("azure: %+v", rs)
	}

	rs, _ = parseGitLabCI(".gitlab-ci.yml", "variables: {A: b}\nbuild:\n  script: [make]\n.tmpl:\n  script: [x]\n")
	if len(rs) != 3 || rs[0].Attrs["build"] != nil {
		t.Fatalf("gitlab: %+v", rs)
	}

	if _, syntax := parseCircleCI(".circleci/config.yml", "jobs: [\n"); len(syntax) != 1 {
		t.Error("circleci syntax error not reported")
	}
}

func TestGitHubUntrusted(t *testing.T) {
	for s, want := range map[string]bool{
		"${{ github.event.issue.title }}":            true,
		"${{github.head_ref}}":                       true,
		"${{ github.event.commits[0].message }}":     true,
		"${{ github.event.pull_request.number }}":    false,
		"$TITLE ${{ github.event.issue.title_id }} ": false,
	} {
		if got := ghUntrusted(s) != ""; got != want {
			t.Errorf("ghUntrusted(%q) = %v", s, got)
		}
	}
}
