package engine

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CI pipelines keep their YAML as written. Every multi-line string also gets
// Lines["<path>@N"], the line of its Nth line, so script findings point at
// the right line.
//
// The file resource holds the top-level keys and leaves the jobs to their own
// resources, so nothing is checked twice.
// GitHub Actions: github_workflow (top level plus triggers, the event names
// under on, and jobs reduced to permissions and steps {uses, run, sbom}) and
// github_job per job (the job plus triggers and workflow_permissions).
// GitLab CI: gitlab_ci (global keywords) and gitlab_job per job.
// Azure Pipelines: azure_pipeline (top level without jobs and stages) and
// azure_pipeline_job per job under jobs or stages[].jobs.
// CircleCI: circleci_config (top level without jobs) and circleci_job per job.
// Bitbucket: bitbucket_pipeline (top level without pipelines) and
// bitbucket_step per step.

func init() {
	formatParsers[FormatGitHubActions] = parseGitHubActions
	formatParsers[FormatGitLabCI] = parseGitLabCI
	formatParsers[FormatAzurePipelines] = parseAzurePipelines
	formatParsers[FormatCircleCI] = parseCircleCI
	formatParsers[FormatBitbucket] = parseBitbucket
}

var ciBlockRE = regexp.MustCompile(`[|>][-+0-9]*\s*(#.*)?$`)

// ciDocs decodes the file and adds per-line entries for multi-line strings.
func ciDocs(name, src, format string) ([]docValue, []Finding) {
	docs, err := decodeYAMLDocs(src)
	if err != nil {
		return docs, []Finding{formatSyntax(name, format, err)}
	}
	srcLines := strings.Split(src, "\n")
	for _, d := range docs {
		for p, l := range d.lines {
			s, ok := get(d.value, p).(string)
			if !ok || !strings.Contains(s, "\n") || l < 1 || l > len(srcLines) {
				continue
			}
			start := l
			if ciBlockRE.MatchString(strings.TrimSpace(srcLines[l-1])) {
				start++
			}
			for i := range strings.Split(s, "\n") {
				d.lines[p+"@"+strconv.Itoa(i)] = start + i
			}
		}
	}
	return docs, nil
}

func ciFile(typ, name string, doc map[string]any, lines map[string]int) *Resource {
	base := strings.TrimSuffix(path.Base(name), path.Ext(name))
	return &Resource{Type: typ, Name: base, Address: typ + "." + base, File: name, Line: 1, Attrs: doc, Lines: lines, Mode: "managed"}
}

func ciChild(typ, name, file string, attrs map[string]any, lines map[string]int, prefix string) *Resource {
	return &Resource{Type: typ, Name: name, Address: typ + "." + name, File: file, Line: lines[prefix], Attrs: attrs,
		Lines: subLines(lines, prefix), Mode: "managed"}
}

func ciKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ciCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+2)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func ghTriggers(on any) []any {
	var out []any
	switch t := on.(type) {
	case string:
		out = append(out, t)
	case []any:
		out = append(out, t...)
	case map[string]any:
		for _, k := range ciKeys(t) {
			out = append(out, k)
		}
	}
	return out
}

func parseGitHubActions(name, src string) ([]*Resource, []Finding) {
	docs, syntax := ciDocs(name, src, "GitHub Actions workflow")
	var out []*Resource
	for _, d := range docs {
		doc, ok := d.value.(map[string]any)
		if !ok {
			continue
		}
		wf := ciFile("github_workflow", name, ciCopy(doc), d.lines)
		triggers := ghTriggers(doc["on"])
		wf.Attrs["triggers"] = triggers
		jobs, _ := doc["jobs"].(map[string]any)
		brief := map[string]any{}
		for id, j := range jobs {
			var steps []any
			for _, st := range asList(get(j, "steps")) {
				steps = append(steps, map[string]any{"uses": get(st, "uses"), "run": get(st, "run"), "sbom": get(st, "with.sbom")})
			}
			brief[id] = map[string]any{"permissions": get(j, "permissions"), "steps": steps}
		}
		wf.Attrs["jobs"] = brief
		out = append(out, wf)
		for _, id := range ciKeys(jobs) {
			j, ok := jobs[id].(map[string]any)
			if !ok {
				continue
			}
			attrs := ciCopy(j)
			attrs["triggers"] = triggers
			if p, ok := doc["permissions"]; ok {
				attrs["workflow_permissions"] = p
			}
			out = append(out, ciChild("github_job", id, name, attrs, d.lines, "jobs."+id))
		}
	}
	return out, syntax
}

var gitlabReserved = map[string]bool{"image": true, "services": true, "stages": true, "types": true, "before_script": true,
	"after_script": true, "variables": true, "cache": true, "include": true, "default": true, "workflow": true, "spec": true}

func parseGitLabCI(name, src string) ([]*Resource, []Finding) {
	docs, syntax := ciDocs(name, src, "GitLab CI")
	var out []*Resource
	for _, d := range docs {
		doc, ok := d.value.(map[string]any)
		if !ok {
			continue
		}
		top := map[string]any{}
		for k, v := range doc {
			if _, job := v.(map[string]any); gitlabReserved[k] || !job {
				top[k] = v
			}
		}
		out = append(out, ciFile("gitlab_ci", name, top, d.lines))
		for _, k := range ciKeys(doc) {
			if j, ok := doc[k].(map[string]any); ok && !gitlabReserved[k] {
				out = append(out, ciChild("gitlab_job", k, name, j, d.lines, k))
			}
		}
	}
	return out, syntax
}

func parseAzurePipelines(name, src string) ([]*Resource, []Finding) {
	docs, syntax := ciDocs(name, src, "Azure Pipelines")
	var out []*Resource
	seen := map[string]bool{}
	for _, d := range docs {
		doc, ok := d.value.(map[string]any)
		if !ok {
			continue
		}
		top := ciCopy(doc)
		delete(top, "jobs")
		delete(top, "stages")
		out = append(out, ciFile("azure_pipeline", name, top, d.lines))
		addJobs := func(list any, prefix string) {
			for i, e := range asList(list) {
				j, ok := e.(map[string]any)
				if !ok {
					continue
				}
				id := ""
				for _, k := range []string{"job", "deployment", "template"} {
					if s, ok := j[k].(string); ok && id == "" {
						id = s
					}
				}
				if id == "" || seen[id] {
					id = strings.ReplaceAll(prefix, ".", "_") + "_" + strconv.Itoa(i)
				}
				seen[id] = true
				out = append(out, ciChild("azure_pipeline_job", id, name, j, d.lines, prefix+"."+strconv.Itoa(i)))
			}
		}
		addJobs(doc["jobs"], "jobs")
		for i, s := range asList(doc["stages"]) {
			if m, ok := s.(map[string]any); ok {
				addJobs(m["jobs"], "stages."+strconv.Itoa(i)+".jobs")
			}
		}
	}
	return out, syntax
}

func parseCircleCI(name, src string) ([]*Resource, []Finding) {
	docs, syntax := ciDocs(name, src, "CircleCI config")
	var out []*Resource
	for _, d := range docs {
		doc, ok := d.value.(map[string]any)
		if !ok {
			continue
		}
		top := ciCopy(doc)
		delete(top, "jobs")
		out = append(out, ciFile("circleci_config", name, top, d.lines))
		jobs, _ := doc["jobs"].(map[string]any)
		for _, id := range ciKeys(jobs) {
			if j, ok := jobs[id].(map[string]any); ok {
				out = append(out, ciChild("circleci_job", id, name, j, d.lines, "jobs."+id))
			}
		}
	}
	return out, syntax
}

func parseBitbucket(name, src string) ([]*Resource, []Finding) {
	docs, syntax := ciDocs(name, src, "Bitbucket Pipelines")
	var out []*Resource
	seen := map[string]bool{}
	for _, d := range docs {
		doc, ok := d.value.(map[string]any)
		if !ok {
			continue
		}
		top := ciCopy(doc)
		delete(top, "pipelines")
		out = append(out, ciFile("bitbucket_pipeline", name, top, d.lines))
		var walk func(v any, p string)
		walk = func(v any, p string) {
			switch t := v.(type) {
			case []any:
				for i, e := range t {
					walk(e, p+"."+strconv.Itoa(i))
				}
			case map[string]any:
				if st, ok := t["step"].(map[string]any); ok {
					id, _ := st["name"].(string)
					id = strings.Join(strings.Fields(id), "_")
					if id == "" || seen[id] {
						id = strings.ReplaceAll(strings.TrimPrefix(p, "pipelines."), ".", "_")
					}
					seen[id] = true
					out = append(out, ciChild("bitbucket_step", id, name, st, d.lines, p+".step"))
					return
				}
				for _, k := range []string{"parallel", "stage", "steps"} {
					if x, ok := t[k]; ok {
						walk(x, p+"."+k)
					}
				}
			}
		}
		pipes, _ := doc["pipelines"].(map[string]any)
		for _, sec := range ciKeys(pipes) {
			if sec == "default" {
				walk(pipes[sec], "pipelines.default")
				continue
			}
			group, _ := pipes[sec].(map[string]any)
			for _, k := range ciKeys(group) {
				walk(group[k], "pipelines."+sec+"."+k)
			}
		}
	}
	return out, syntax
}
