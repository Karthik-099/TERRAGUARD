package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Rules for CI pipelines (resource shapes in format_ci.go).

func init() { registerForeign(ciForeign) }

// ciRuleSet is every CI pipeline rule, including the checks shared by all CI formats.
func ciRuleSet() []Rule {
	var rs []Rule
	rs = append(rs, ghaRules...)
	rs = append(rs, ciCommon("TG-GHA", []string{"github_job", "github_workflow"}, map[string]int{"netcat": 4, "pipe": 13, "tls": 14, "latest": 17, "digest": 18})...)
	rs = append(rs, gitlabRules...)
	rs = append(rs, ciCommon("TG-GITLAB", []string{"gitlab_job", "gitlab_ci"}, map[string]int{"latest": 3, "digest": 4, "pipe": 5, "tls": 6, "netcat": 7, "secret": 8})...)
	rs = append(rs, azpRules...)
	rs = append(rs, ciCommon("TG-AZP", []string{"azure_pipeline_job", "azure_pipeline"}, map[string]int{"latest": 1, "digest": 2, "pipe": 4, "tls": 5, "netcat": 6, "secret": 7})...)
	rs = append(rs, circleRules...)
	rs = append(rs, ciCommon("TG-CIRCLE", []string{"circleci_job", "circleci_config"}, map[string]int{"latest": 1, "digest": 2, "netcat": 5, "pipe": 8, "tls": 9})...)
	rs = append(rs, ciCommon("TG-BB", []string{"bitbucket_step", "bitbucket_pipeline"}, map[string]int{"latest": 1, "digest": 2, "pipe": 3, "tls": 4, "netcat": 5})...)
	return rs
}

var ciForeign = map[string][]string{
	"CKV_GHA_1": {"TG-GHA-001"}, "CKV_GHA_2": {"TG-GHA-002"}, "CKV_GHA_3": {"TG-GHA-003"}, "CKV_GHA_4": {"TG-GHA-004"},
	"CKV_GHA_5": {"TG-GHA-005"}, "CKV_GHA_6": {"TG-GHA-006"}, "CKV_GHA_7": {"TG-GHA-007"}, "CKV2_GHA_1": {"TG-GHA-008", "TG-GHA-009"},
	"CKV_GITLABCI_1": {"TG-GITLAB-001"}, "CKV_GITLABCI_2": {"TG-GITLAB-002"}, "CKV_GITLABCI_3": {"TG-GITLAB-003", "TG-GITLAB-004"},
	"CKV_AZUREPIPELINES_1": {"TG-AZP-001"}, "CKV_AZUREPIPELINES_2": {"TG-AZP-001", "TG-AZP-002"}, "CKV_AZUREPIPELINES_3": {"TG-AZP-003"},
	"CKV_AZUREPIPELINES_5":    {"TG-AZP-001", "TG-AZP-002"},
	"CKV_CIRCLECIPIPELINES_1": {"TG-CIRCLE-001"}, "CKV_CIRCLECIPIPELINES_2": {"TG-CIRCLE-001", "TG-CIRCLE-002"},
	"CKV_CIRCLECIPIPELINES_3": {"TG-CIRCLE-003"}, "CKV_CIRCLECIPIPELINES_4": {"TG-CIRCLE-004"}, "CKV_CIRCLECIPIPELINES_5": {"TG-CIRCLE-005"},
	"CKV_CIRCLECIPIPELINES_6": {"TG-CIRCLE-006"}, "CKV_CIRCLECIPIPELINES_7": {"TG-CIRCLE-007"},
	"CKV_CIRCLECIPIPELINES_8": {"TG-CIRCLE-001", "TG-CIRCLE-002"}, "CKV_BITBUCKETPIPELINES_1": {"TG-BB-001"},
}

// ciText is a value found at a path: a script, an image or a variable.
type ciText struct {
	path, key string
	val       any
	nested    bool // the value is not directly under its name (GitLab {value}, Azure [{name, value}])
}

func ciAt(r *Resource, p string, i int) string {
	if _, ok := r.Lines[p+"@"+strconv.Itoa(i)]; ok {
		return p + "@" + strconv.Itoa(i)
	}
	return p
}

func ciIdx(p string, i int) string { return p + "." + strconv.Itoa(i) }

// ciStrings collects a string or a (nested) list of strings.
func ciStrings(v any, p string) []ciText {
	switch t := v.(type) {
	case string:
		return []ciText{{path: p, val: t}}
	case []any:
		var out []ciText
		for i, e := range t {
			out = append(out, ciStrings(e, ciIdx(p, i))...)
		}
		return out
	}
	return nil
}

func ciSteps(r *Resource, key string) []map[string]any {
	var out []map[string]any
	for _, s := range asList(r.Attrs[key]) {
		m, _ := s.(map[string]any)
		out = append(out, m) // nil keeps indexes aligned
	}
	return out
}

// ciScripts lists the shell scripts a resource runs.
func ciScripts(r *Resource) []ciText {
	var out []ciText
	switch r.Type {
	case "github_job":
		for i, s := range ciSteps(r, "steps") {
			out = append(out, ciStrings(s["run"], ciIdx("steps", i)+".run")...)
		}
	case "gitlab_job", "gitlab_ci":
		for _, k := range []string{"script", "before_script", "after_script"} {
			out = append(out, ciStrings(r.Attrs[k], k)...)
		}
		if r.Type == "gitlab_ci" {
			for _, k := range []string{"before_script", "after_script"} {
				out = append(out, ciStrings(r.get("default."+k), "default."+k)...)
			}
		}
	case "azure_pipeline_job", "azure_pipeline":
		var walk func(v any, p string)
		walk = func(v any, p string) {
			switch t := v.(type) {
			case []any:
				for i, e := range t {
					walk(e, ciIdx(p, i))
				}
			case map[string]any:
				for _, k := range ciKeys(t) {
					switch {
					case k == "script" || k == "bash" || k == "powershell" || k == "pwsh" || k == "inlineScript" || k == "Inline":
						out = append(out, ciStrings(t[k], p+"."+k)...)
					case k == "steps" || k == "inputs" || k == "strategy" || k == "runOnce" || k == "deploy" || k == "rolling" || k == "canary":
						walk(t[k], strings.TrimPrefix(p+"."+k, "."))
					}
				}
			}
		}
		if r.Type == "azure_pipeline" {
			walk(r.Attrs["steps"], "steps")
		} else {
			walk(r.Attrs, "")
		}
	case "circleci_job":
		for i, s := range ciSteps(r, "steps") {
			p := ciIdx("steps", i) + ".run"
			switch run := s["run"].(type) {
			case string:
				out = append(out, ciText{path: p, val: run})
			case map[string]any:
				out = append(out, ciStrings(run["command"], p+".command")...)
			}
		}
	case "bitbucket_step":
		for _, k := range []string{"script", "after-script"} {
			out = append(out, ciStrings(r.Attrs[k], k)...)
		}
	}
	return out
}

func ciImageOf(v any, p string, keys ...string) []ciText {
	if s, ok := v.(string); ok {
		return []ciText{{path: p, val: s}}
	}
	if m, ok := v.(map[string]any); ok {
		for _, k := range keys {
			if s, ok := m[k].(string); ok {
				return []ciText{{path: p + "." + k, val: s}}
			}
		}
	}
	return nil
}

// ciImages lists the container images a resource runs.
func ciImages(r *Resource) []ciText {
	var out []ciText
	switch r.Type {
	case "github_job":
		out = append(out, ciImageOf(r.Attrs["container"], "container", "image")...)
		svcs, _ := r.Attrs["services"].(map[string]any)
		for _, k := range ciKeys(svcs) {
			out = append(out, ciImageOf(svcs[k], "services."+k, "image")...)
		}
		for i, s := range ciSteps(r, "steps") {
			if u, _ := s["uses"].(string); strings.HasPrefix(u, "docker://") {
				out = append(out, ciText{path: ciIdx("steps", i) + ".uses", val: strings.TrimPrefix(u, "docker://")})
			}
		}
	case "gitlab_job", "gitlab_ci":
		for _, pre := range []string{"", "default."} {
			if pre != "" && r.Type == "gitlab_job" {
				continue
			}
			out = append(out, ciImageOf(r.get(pre+"image"), pre+"image", "name")...)
			for i, s := range asList(r.get(pre + "services")) {
				out = append(out, ciImageOf(s, ciIdx(pre+"services", i), "name")...)
			}
		}
	case "azure_pipeline_job", "azure_pipeline":
		out = append(out, ciImageOf(r.Attrs["container"], "container", "image")...)
		if r.Type == "azure_pipeline" {
			for i, c := range asList(r.get("resources.containers")) {
				out = append(out, ciImageOf(get(c, "image"), ciIdx("resources.containers", i)+".image")...)
			}
		}
	case "circleci_job":
		for i, d := range asList(r.Attrs["docker"]) {
			out = append(out, ciImageOf(get(d, "image"), ciIdx("docker", i)+".image")...)
		}
	case "circleci_config":
		ex, _ := r.Attrs["executors"].(map[string]any)
		for _, k := range ciKeys(ex) {
			for i, d := range asList(get(ex[k], "docker")) {
				out = append(out, ciImageOf(get(d, "image"), ciIdx("executors."+k+".docker", i)+".image")...)
			}
		}
	case "bitbucket_step", "bitbucket_pipeline":
		out = append(out, ciImageOf(r.Attrs["image"], "image", "name")...)
		if r.Type == "bitbucket_pipeline" {
			svcs, _ := r.get("definitions.services").(map[string]any)
			for _, k := range ciKeys(svcs) {
				out = append(out, ciImageOf(get(svcs[k], "image"), "definitions.services."+k+".image", "name")...)
			}
		}
	}
	return out
}

func ciMapVars(v any, p string) []ciText {
	var out []ciText
	switch t := v.(type) {
	case map[string]any:
		for _, k := range ciKeys(t) {
			if m, ok := t[k].(map[string]any); ok { // GitLab {value: ..., description: ...}
				out = append(out, ciText{path: p + "." + k + ".value", key: k, val: m["value"], nested: true})
				continue
			}
			out = append(out, ciText{path: p + "." + k, key: k, val: t[k]})
		}
	case []any: // Azure [{name, value}]
		for i, e := range t {
			if m, ok := e.(map[string]any); ok {
				if n, ok := m["name"].(string); ok {
					out = append(out, ciText{path: ciIdx(p, i) + ".value", key: n, val: m["value"], nested: true})
				}
			}
		}
	}
	return out
}

// ciVars lists variables and credentials written in the pipeline.
func ciVars(r *Resource) []ciText {
	var out []ciText
	pw := func(v any, p string) {
		if s, ok := v.(string); ok {
			out = append(out, ciText{path: p, key: "password", val: s})
		}
	}
	switch r.Type {
	case "github_workflow":
		out = append(out, ciMapVars(r.Attrs["env"], "env")...)
	case "github_job":
		out = append(out, ciMapVars(r.Attrs["env"], "env")...)
		out = append(out, ciMapVars(r.get("container.env"), "container.env")...)
		pw(r.get("container.credentials.password"), "container.credentials.password")
		svcs, _ := r.Attrs["services"].(map[string]any)
		for _, k := range ciKeys(svcs) {
			out = append(out, ciMapVars(get(svcs[k], "env"), "services."+k+".env")...)
			pw(get(svcs[k], "credentials.password"), "services."+k+".credentials.password")
		}
		for i, s := range ciSteps(r, "steps") {
			out = append(out, ciMapVars(s["env"], ciIdx("steps", i)+".env")...)
		}
	case "gitlab_job", "gitlab_ci", "azure_pipeline_job", "azure_pipeline":
		out = append(out, ciMapVars(r.Attrs["variables"], "variables")...)
	case "circleci_job":
		out = append(out, ciMapVars(r.Attrs["environment"], "environment")...)
		for i, d := range asList(r.Attrs["docker"]) {
			out = append(out, ciMapVars(get(d, "environment"), ciIdx("docker", i)+".environment")...)
			pw(get(d, "auth.password"), ciIdx("docker", i)+".auth.password")
		}
	case "bitbucket_step", "bitbucket_pipeline":
		pw(r.get("image.password"), "image.password")
	}
	return out
}

// ciScriptLine finds the first script line that matches.
func ciScriptLine(r *Resource, match func(line string) bool, msg string) []Hit {
	var out []Hit
	for _, s := range ciScripts(r) {
		text, _ := s.val.(string)
		for i, l := range strings.Split(text, "\n") {
			if match(l) {
				out = append(out, Hit{Path: ciAt(r, s.path, i), Msg: msg})
				break
			}
		}
	}
	return out
}

func ciID(prefix string, n int) string { return fmt.Sprintf("%s-%03d", prefix, n) }

// ciCommon builds the rules every CI format shares, numbered per format.
func ciCommon(prefix string, types []string, ids map[string]int) []Rule {
	var out []Rule
	for _, r := range ciCommonAll(prefix, types, ids) {
		if !strings.HasSuffix(r.ID, "-000") { // kinds a format does not use
			out = append(out, r)
		}
	}
	return out
}

func ciCommonAll(prefix string, types []string, ids map[string]int) []Rule {
	return []Rule{
		{ID: ciID(prefix, ids["pipe"]), Title: "Pipeline pipes a downloaded script into a shell", Severity: Medium, Category: CatSecurity, CWE: "CWE-494", Types: types,
			Remediation: "Download the script, verify its checksum or signature, then run it; or use a pinned release.",
			Check: func(r *Resource) []Hit {
				return ciScriptLine(r, pipeShellRE.MatchString, "Whatever the server returns runs with the pipeline's credentials, unreviewed.")
			}},
		{ID: ciID(prefix, ids["tls"]), Title: "Pipeline disables certificate validation", Severity: High, Category: CatSecurity, CWE: "CWE-295", Types: types,
			Remediation: "Remove -k/--insecure, --no-check-certificate, --trusted-host and similar; install the CA certificate instead.",
			Check: func(r *Resource) []Hit {
				out := ciScriptLine(r, tlsOffText, "Downloads accept any certificate, so a network attacker can swap what the pipeline runs or ships.")
				for _, v := range ciVars(r) {
					if s, ok := v.val.(string); ok && tlsOffEnv(v.key, s) {
						out = append(out, Hit{Path: v.path, Msg: v.key + " turns off certificate checks for the pipeline."})
					}
				}
				return out
			}},
		{ID: ciID(prefix, ids["netcat"]), Title: "Pipeline opens a netcat connection to an IP address", Severity: High, Category: CatSecurity, CWE: "CWE-506", Types: types,
			Remediation: "Remove the netcat call; it is the usual shape of a reverse shell.",
			Check: func(r *Resource) []Hit {
				return ciScriptLine(r, reverseShell, "A raw connection to a fixed address can hand the runner and its secrets to someone else.")
			}},
		{ID: ciID(prefix, ids["latest"]), Title: "Pipeline image uses the latest tag or no tag", Severity: Medium, Category: CatSecurity, CWE: "CWE-1357", Types: types,
			Remediation: "Pin the image to a version tag, ideally with a digest (image:1.2.3@sha256:...).",
			Check: func(r *Resource) []Hit {
				var out []Hit
				for _, im := range ciImages(r) {
					if s, _ := im.val.(string); imageRef(s) == "latest" {
						out = append(out, Hit{Path: im.path, Msg: "Each run can pull a different " + s + "."})
					}
				}
				return out
			}},
		{ID: ciID(prefix, ids["digest"]), Title: "Pipeline image is not pinned by digest", Severity: Low, Category: CatSecurity, CWE: "CWE-1357", Types: types,
			Remediation: "Add the digest to the image (image:1.2.3@sha256:...).",
			Check: func(r *Resource) []Hit {
				var out []Hit
				for _, im := range ciImages(r) {
					if s, _ := im.val.(string); imageRef(s) == "tag" {
						out = append(out, Hit{Path: im.path, Msg: "A tag can be moved to a different image; " + s + " is trusted without a content hash."})
					}
				}
				return out
			}},
		{ID: ciID(prefix, ids["secret"]), Title: "Secret written in a pipeline variable", Severity: High, Category: CatSecurity, CWE: "CWE-798", Types: types,
			Remediation: "Store the value in the CI system's secret store and reference it.",
			Check: func(r *Resource) []Hit {
				var out []Hit
				for _, v := range ciVars(r) {
					if v.nested && literalSecret(v.key, v.val) { // plain name: value pairs are covered by TG-SEC-001
						out = append(out, Hit{Path: v.path, Msg: v.key + " is committed in plain text, so everyone with read access has it."})
					}
				}
				return out
			}},
	}
}

var (
	ghExprRE      = regexp.MustCompile(`\$\{\{([^}]*)\}\}`)
	ghUntrustedRE = regexp.MustCompile(`\bgithub\.(?:head_ref\b|event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages(?:\.\*|\[\d+\]|\[\*\])?\.page_name|head_commit\.(?:message|author\.(?:email|name))|commits(?:\.\*|\[\d+\]|\[\*\])?\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name))))\b)`)
	ghHeadRefRE   = regexp.MustCompile(`github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch)|refs/pull/`)
	ghShaRE       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	ghBuildCmds   = []string{"docker build", "docker buildx build", "ko build", "buildah bud", "buildah build", "podman build", "podman image build", "nerdctl build"}
	ciPipeSrcRE   = regexp.MustCompile(`^\$CI_PIPELINE_SOURCE\s*==\s*["'](?:merge_request_event|push)["']`)
	circleInjRE   = regexp.MustCompile(`<<\s*pipeline\.(?:git\.(?:branch|tag)|trigger_parameters\.[^>]*)\s*>>`)
)

func ghUntrusted(s string) string {
	for _, m := range ghExprRE.FindAllStringSubmatch(s, -1) {
		if u := ghUntrustedRE.FindString(m[1]); u != "" {
			return u
		}
	}
	return ""
}

func ghTriggered(r *Resource, events ...string) bool {
	return contains(asStrings(r.Attrs["triggers"]), events...)
}

// ghWorkflowSteps lists every step of every job in a workflow file.
func ghWorkflowSteps(r *Resource) []ciText {
	var out []ciText
	jobs, _ := r.Attrs["jobs"].(map[string]any)
	for _, id := range ciKeys(jobs) {
		for i, s := range asList(get(jobs[id], "steps")) {
			out = append(out, ciText{path: ciIdx("jobs."+id+".steps", i), val: s})
		}
	}
	return out
}

func ghStepText(s any) (uses, run string) {
	m, _ := s.(map[string]any)
	uses, _ = m["uses"].(string)
	run, _ = m["run"].(string)
	return
}

func ghEnvHits(env any, p string) []Hit {
	m, _ := env.(map[string]any)
	if v, ok := m["ACTIONS_ALLOW_UNSECURE_COMMANDS"]; ok && is(v, true) {
		return []Hit{{Path: p + ".ACTIONS_ALLOW_UNSECURE_COMMANDS", Msg: "Workflow commands set-env and add-path are re-enabled, so log output can inject environment variables."}}
	}
	return nil
}

// ghSupplyChain flags the first image build when no step shows the evidence.
func ghSupplyChain(r *Resource, evidence func(uses, run string, sbom any) bool, msg string) []Hit {
	build := ""
	for _, s := range ghWorkflowSteps(r) {
		uses, run := ghStepText(s.val)
		if evidence(uses, run, get(s.val, "sbom")) {
			return nil
		}
		if build == "" && (strings.Contains(uses, "docker/build-push-action") || strings.Contains(uses, "docker/bake-action") || ghBuilds(run)) {
			build = s.path
		}
	}
	if build != "" {
		return []Hit{{Path: build, Msg: msg}}
	}
	return nil
}

func ghBuilds(run string) bool {
	for _, c := range ghBuildCmds {
		if strings.Contains(run, c) {
			return true
		}
	}
	return false
}

var (
	ghJobT = []string{"github_job"}
	ghWfT  = []string{"github_workflow"}
)

var ghaRules = []Rule{
	{ID: "TG-GHA-001", Title: "Deprecated unsafe workflow commands are enabled", Severity: High, Category: CatSecurity, CWE: "CWE-77", Types: []string{"github_job", "github_workflow"},
		Remediation: "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and write to $GITHUB_ENV and $GITHUB_PATH instead.",
		Check: func(r *Resource) []Hit {
			out := ghEnvHits(r.Attrs["env"], "env")
			if r.Type == "github_job" {
				for i, s := range ciSteps(r, "steps") {
					out = append(out, ghEnvHits(s["env"], ciIdx("steps", i)+".env")...)
				}
			}
			return out
		}},
	{ID: "TG-GHA-002", Title: "Untrusted event data is expanded into a script", Severity: High, Category: CatSecurity, CWE: "CWE-78", Types: ghJobT,
		Remediation: "Pass the value through env (env: TITLE: ${{ github.event.issue.title }}) and use \"$TITLE\" in the script.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for i, s := range ciSteps(r, "steps") {
				for _, t := range append(ciStrings(s["run"], ciIdx("steps", i)+".run"), ciStrings(get(s, "with.script"), ciIdx("steps", i)+".with.script")...) {
					text, _ := t.val.(string)
					for li, l := range strings.Split(text, "\n") {
						if u := ghUntrusted(l); u != "" {
							out = append(out, Hit{Path: ciAt(r, t.path, li), Msg: u + " is pasted into the script before it runs, so anyone who can set it can run commands with the job's token and secrets."})
							break
						}
					}
				}
			}
			return out
		}},
	{ID: "TG-GHA-003", Title: "curl call carries a secret", Severity: Low, Category: CatSecurity, CWE: "CWE-200", Types: ghJobT,
		Remediation: "Check the destination is trusted; prefer an official action or pass the secret in a header from env.",
		Check: func(r *Resource) []Hit {
			return ciScriptLine(r, func(l string) bool {
				return strings.Contains(l, "curl") && strings.Contains(strings.ToLower(l), "secret")
			},
				"A secret sent with curl goes wherever the URL points, including a changed or attacker-controlled one.")
		}},
	{ID: "TG-GHA-005", Title: "Container image is built but not signed", Severity: Low, Category: CatSecurity, CWE: "CWE-345", Types: ghWfT,
		Remediation: "Sign the pushed image (cosign sign or actions/attest-build-provenance).",
		Check: func(r *Resource) []Hit {
			return ghSupplyChain(r, func(uses, run string, _ any) bool {
				return strings.Contains(run, "cosign sign") || strings.Contains(uses, "actions/attest-build-provenance")
			}, "Consumers cannot verify that the image came from this pipeline.")
		}},
	{ID: "TG-GHA-006", Title: "Container image is built without an SBOM attestation", Severity: Low, Category: CatSecurity, CWE: "CWE-1357", Types: ghWfT,
		Remediation: "Attest an SBOM for the image (cosign attest --type spdx, actions/attest-sbom, or build-push-action with sbom: true).",
		Check: func(r *Resource) []Hit {
			return ghSupplyChain(r, func(uses, run string, sbom any) bool {
				return strings.Contains(run, "cosign") && strings.Contains(run, "sbom") || strings.Contains(uses, "actions/attest-sbom") || is(sbom, true)
			}, "Consumers cannot check what the image contains when a vulnerability is announced.")
		}},
	{ID: "TG-GHA-007", Title: "Manual run accepts build inputs", Severity: Info, Category: CatSecurity, CWE: "CWE-15", Types: ghWfT,
		Remediation: "Remove workflow_dispatch inputs from release builds, or validate every input before use.",
		Check: func(r *Resource) []Hit {
			if m, ok := r.get("on.workflow_dispatch.inputs").(map[string]any); ok && len(m) > 0 {
				return []Hit{{Path: "on.workflow_dispatch.inputs", Msg: "The output can depend on values typed at run time rather than on the source."}}
			}
			return nil
		}},
	{ID: "TG-GHA-008", Title: "GITHUB_TOKEN is granted write-all", Severity: High, Category: CatSecurity, CWE: "CWE-250", Types: []string{"github_job", "github_workflow"},
		Remediation: "Set permissions to the scopes the job needs, for example permissions: { contents: read }.",
		Check: func(r *Resource) []Hit {
			if s, _ := r.Attrs["permissions"].(string); s == "write-all" {
				return []Hit{{Path: "permissions", Msg: "Any compromised step can push code, create releases and change repository settings."}}
			}
			return nil
		}},
	{ID: "TG-GHA-009", Title: "GITHUB_TOKEN permissions are not set", Severity: Low, Category: CatSecurity, CWE: "CWE-250", Types: ghWfT,
		Remediation: "Add a top-level permissions block (for example permissions: { contents: read }) and widen it per job.",
		Check: func(r *Resource) []Hit {
			if _, ok := r.Attrs["permissions"]; ok {
				return nil
			}
			jobs, _ := r.Attrs["jobs"].(map[string]any)
			for _, id := range ciKeys(jobs) {
				if m, _ := jobs[id].(map[string]any); m["permissions"] == nil {
					return []Hit{{Path: "jobs." + id, Msg: "The job gets the repository default, which is write access on older repositories and organizations."}}
				}
			}
			return nil
		}},
	{ID: "TG-GHA-010", Title: "Privileged trigger checks out pull request code", Severity: Critical, Category: CatSecurity, CWE: "CWE-829", Types: ghJobT,
		Remediation: "Use pull_request for untrusted code, or split into a pull_request build and a workflow_run job that only reads its artifacts.",
		Check: func(r *Resource) []Hit {
			if !ghTriggered(r, "pull_request_target", "workflow_run") {
				return nil
			}
			for i, s := range ciSteps(r, "steps") {
				uses, run := ghStepText(s)
				ref, _ := get(s, "with.ref").(string)
				if strings.Contains(uses, "actions/checkout") && ghHeadRefRE.MatchString(ref) ||
					strings.Contains(run, "gh pr checkout") || ghHeadRefRE.MatchString(run) && strings.Contains(run, "git ") {
					return []Hit{{Path: ciIdx("steps", i), Msg: "Code from the pull request runs with a write token and the repository's secrets."}}
				}
			}
			return nil
		}},
	{ID: "TG-GHA-011", Title: "Action is not pinned to a commit SHA", Severity: Low, Category: CatSecurity, CWE: "CWE-829", Types: ghJobT,
		Remediation: "Pin uses: to the full 40-character commit SHA (keep the version in a comment) and update it with a dependency bot.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			check := func(uses, p string) {
				if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
					return
				}
				_, ref, _ := strings.Cut(uses, "@")
				if ghShaRE.MatchString(ref) {
					return
				}
				h := Hit{Path: p, Msg: uses + " runs whatever the tag points to; if the action's repository is compromised, so is this job."}
				if strings.HasPrefix(uses, "actions/") || strings.HasPrefix(uses, "github/") {
					h.Sev = Low
				}
				out = append(out, h)
			}
			u, _ := r.Attrs["uses"].(string)
			check(u, "uses")
			for i, s := range ciSteps(r, "steps") {
				u, _ := s["uses"].(string)
				check(u, ciIdx("steps", i)+".uses")
			}
			return out
		}},
	{ID: "TG-GHA-012", Title: "Secret printed to the log", Severity: Medium, Category: CatSecurity, CWE: "CWE-532", Types: ghJobT,
		Remediation: "Do not echo secrets; pass them through env to the tool that needs them.",
		Check: func(r *Resource) []Hit {
			return ciScriptLine(r, func(l string) bool {
				t := strings.TrimSpace(l)
				return strings.Contains(t, "secrets.") && strings.Contains(t, "${{") && !strings.ContainsAny(t, ">|") && !strings.Contains(t, "add-mask") &&
					(strings.HasPrefix(t, "echo ") || strings.HasPrefix(t, "printf ") || strings.HasPrefix(t, "Write-Host ") || strings.HasPrefix(t, "Write-Output "))
			}, "Log masking misses transformed values (base64, substrings), so the secret can end up readable in the log.")
		}},
	{ID: "TG-GHA-015", Title: "Self-hosted runner runs pull request code", Severity: Medium, Category: CatSecurity, CWE: "CWE-829", Types: ghJobT,
		Remediation: "Use GitHub-hosted or ephemeral runners for pull_request jobs, or require approval for outside contributors.",
		Check: func(r *Resource) []Hit {
			labels := asStrings(r.Attrs["runs-on"])
			labels = append(labels, asStrings(r.get("runs-on.labels"))...)
			if ghTriggered(r, "pull_request", "pull_request_target") && contains(labels, "self-hosted") {
				return []Hit{{Path: "runs-on", Msg: "A pull request can run code on the runner and leave something behind for the next job."}}
			}
			return nil
		}},
	{ID: "TG-GHA-016", Title: "Reusable workflow inherits every secret", Severity: Low, Category: CatSecurity, CWE: "CWE-250", Types: ghJobT,
		Remediation: "List only the secrets the called workflow needs under secrets:.",
		Check: func(r *Resource) []Hit {
			if s, _ := r.Attrs["secrets"].(string); s == "inherit" && r.Attrs["uses"] != nil {
				return []Hit{{Path: "secrets", Msg: "The called workflow receives all repository and organization secrets."}}
			}
			return nil
		}},
}

var gitlabRules = []Rule{
	{ID: "TG-GITLAB-001", Title: "curl call carries a CI variable", Severity: Medium, Category: CatSecurity, CWE: "CWE-200", Types: []string{"gitlab_job", "gitlab_ci"},
		Remediation: "Check the destination is trusted; never send CI_JOB_TOKEN or other CI variables to outside hosts.",
		Check: func(r *Resource) []Hit {
			return ciScriptLine(r, func(l string) bool {
				return strings.Contains(l, "curl") && (strings.Contains(l, "$CI") || strings.Contains(l, "${CI"))
			}, "CI variables such as CI_JOB_TOKEN go wherever the URL points.")
		}},
	{ID: "TG-GITLAB-002", Title: "Rules can start the pipeline twice", Severity: Low, Category: CatReliability, Types: []string{"gitlab_job", "gitlab_ci"},
		Remediation: "Use one rule for merge requests and exclude branch pipelines with open merge requests ($CI_OPEN_MERGE_REQUESTS).",
		Check: func(r *Resource) []Hit {
			key := "rules"
			if r.Type == "gitlab_ci" {
				key = "workflow.rules"
			}
			n := 0
			for i, rule := range asList(r.get(key)) {
				if s, _ := get(rule, "if").(string); ciPipeSrcRE.MatchString(s) {
					if n++; n > 1 {
						return []Hit{{Path: ciIdx(key, i), Msg: "A push to a branch with an open merge request runs a branch and a merge request pipeline."}}
					}
				}
			}
			return nil
		}},
	{ID: "TG-GITLAB-009", Title: "Included CI configuration is not pinned", Severity: Medium, Category: CatSecurity, CWE: "CWE-829", Types: []string{"gitlab_ci"},
		Remediation: "Include project files with a ref set to a tag or commit SHA, and avoid remote: URLs.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			inc := r.Attrs["include"]
			if _, ok := inc.([]any); !ok && inc != nil {
				inc = []any{inc}
			}
			for i, e := range asList(inc) {
				p := ciIdx("include", i)
				if _, ok := r.Lines[p]; !ok {
					p = "include"
				}
				switch t := e.(type) {
				case string:
					if strings.HasPrefix(t, "http") {
						out = append(out, Hit{Path: p, Msg: "Whoever controls " + t + " controls this pipeline."})
					}
				case map[string]any:
					if t["remote"] != nil {
						out = append(out, Hit{Path: p, Msg: "Whoever controls the remote URL controls this pipeline."})
					} else if t["project"] != nil && t["ref"] == nil {
						out = append(out, Hit{Path: p, Msg: "The included file follows the other project's default branch, so its changes apply here unreviewed.", Sev: Low})
					}
				}
			}
			return out
		}},
	{ID: "TG-GITLAB-010", Title: "Docker-in-Docker runs without TLS", Severity: Medium, Category: CatSecurity, CWE: "CWE-319", Types: []string{"gitlab_job", "gitlab_ci"},
		Remediation: `Keep DOCKER_TLS_CERTDIR: "/certs" so the Docker daemon requires TLS.`,
		Check: func(r *Resource) []Hit {
			for _, v := range ciVars(r) {
				if s, ok := v.val.(string); v.key == "DOCKER_TLS_CERTDIR" && ok && s == "" {
					return []Hit{{Path: v.path, Msg: "The Docker daemon listens without TLS, so other jobs on the network can drive it."}}
				}
			}
			return nil
		}},
}

var azpRules = []Rule{
	{ID: "TG-AZP-003", Title: "Script marks a variable as secret", Severity: Low, Category: CatSecurity, CWE: "CWE-532", Types: []string{"azure_pipeline_job", "azure_pipeline"},
		Remediation: "Keep secrets in a variable group or Key Vault rather than producing them in a script.",
		Check: func(r *Resource) []Hit {
			return ciScriptLine(r, func(l string) bool {
				return strings.Contains(l, "task.setvariable") && strings.Contains(l, "issecret=true")
			}, "The secret value passes through the script and its command line, where it is easy to leak into logs.")
		}},
	{ID: "TG-AZP-008", Title: "Checkout keeps the access token in the repository", Severity: Low, Category: CatSecurity, CWE: "CWE-522", Types: []string{"azure_pipeline_job", "azure_pipeline"},
		Remediation: "Remove persistCredentials: true unless a later step must push.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for i, s := range ciSteps(r, "steps") {
				if s["checkout"] != nil && is(s["persistCredentials"], true) {
					out = append(out, Hit{Path: ciIdx("steps", i) + ".persistCredentials", Msg: "Every later step, including third-party tasks, can read the token from .git/config."})
				}
			}
			return out
		}},
}

var circleRules = []Rule{
	{ID: "TG-CIRCLE-003", Title: "Development orb version in use", Severity: Medium, Category: CatSecurity, CWE: "CWE-829", Types: []string{"circleci_config"},
		Remediation: "Use a released orb version (namespace/orb@1.2.3).",
		Check:       circleOrb("@dev:", "Development orb versions are mutable and expire, so the pipeline runs code that can change at any time.")},
	{ID: "TG-CIRCLE-004", Title: "Orb pinned to volatile", Severity: Medium, Category: CatSecurity, CWE: "CWE-829", Types: []string{"circleci_config"},
		Remediation: "Pin the orb to a released version (namespace/orb@1.2.3).",
		Check:       circleOrb("@volatile", "volatile resolves to the newest release, so a bad orb release reaches this pipeline immediately.")},
	{ID: "TG-CIRCLE-006", Title: "Branch or tag name is expanded into a script", Severity: High, Category: CatSecurity, CWE: "CWE-78", Types: []string{"circleci_job"},
		Remediation: "Read the value from $CIRCLE_BRANCH or $CIRCLE_TAG and quote it, instead of << pipeline.git.* >>.",
		Check: func(r *Resource) []Hit {
			return ciScriptLine(r, circleInjRE.MatchString, "The value is pasted into the script before it runs, so a crafted branch name can run commands.")
		}},
	{ID: "TG-CIRCLE-007", Title: "Script sends data with curl POST", Severity: Low, Category: CatSecurity, CWE: "CWE-200", Types: []string{"circleci_job"},
		Remediation: "Check the destination is trusted and that no secret or source code is sent.",
		Check: func(r *Resource) []Hit {
			return ciScriptLine(r, func(l string) bool { return strings.Contains(l, "curl") && strings.Contains(l, "POST") },
				"Posting from the pipeline is a common way to move secrets out of it.")
		}},
}

func circleOrb(marker, msg string) func(r *Resource) []Hit {
	return func(r *Resource) []Hit {
		orbs, _ := r.Attrs["orbs"].(map[string]any)
		var out []Hit
		for _, k := range ciKeys(orbs) {
			if s, _ := orbs[k].(string); strings.Contains(s, marker) {
				out = append(out, Hit{Path: "orbs." + k, Msg: msg})
			}
		}
		return out
	}
}

// reverseShell is a netcat connection to an address, but not a port probe or a loopback wait loop.
func reverseShell(line string) bool {
	m := netcatRE.FindString(line)
	return m != "" && !ncProbeRE.MatchString(m)
}
