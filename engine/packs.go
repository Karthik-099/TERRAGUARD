package engine

import (
	"fmt"
	"sort"
	"strings"
)

// PolicyPacks are built-in policies a .terraguard.yml can extend, for example
// `extends: [terraguard:recommended]`. They only set the gate and exception
// rules; every rule still runs.
var PolicyPacks = map[string]string{
	// minimal: block only critical risk and changes that will not apply.
	"minimal": "fail_on: CRITICAL\n",
	// recommended: block high risk; exceptions expire; leaked secrets and committed state cannot be waived.
	"recommended": "fail_on: HIGH\nmax_waiver_days: 90\nunwaivable: [TG-SEC-001, TG-SEC-002, TG-STATE-002]\n",
	// strict: block medium risk; short-lived exceptions only in the policy file; public data,
	// wildcard IAM, privileged workloads and script injection cannot be waived.
	"strict": "fail_on: MEDIUM\nmax_waiver_days: 30\ninline_ignores: false\n" +
		"unwaivable: [TG-SEC-*, TG-STATE-002, TG-AWS-S3-001, TG-AWS-RDS-001, TG-AWS-IAM-001, TG-GCP-GCS-001, TG-K8S-001, TG-GHA-002]\n",
}

const packPrefix = "terraguard:"

// PackNames lists the built-in packs.
func PackNames() []string {
	out := make([]string, 0, len(PolicyPacks))
	for k := range PolicyPacks {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// packLoader resolves terraguard:<name> and defers anything else to next.
func packLoader(next func(string) (string, error)) func(string) (string, error) {
	return func(ref string) (string, error) {
		if name, ok := strings.CutPrefix(ref, packPrefix); ok {
			if p, ok := PolicyPacks[name]; ok {
				return p, nil
			}
			return "", fmt.Errorf("unknown pack %q (have %s)", name, strings.Join(PackNames(), ", "))
		}
		if next == nil {
			return "", fmt.Errorf("%s: only built-in packs can be extended here", ref)
		}
		return next(ref)
	}
}
