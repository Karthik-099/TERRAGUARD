package engine

import "fmt"

// RiskWeight sums active findings by severity (the unclamped form of Score),
// so improvements stay measurable even when the score is already 0.
func RiskWeight(r *Report) int {
	w := 0
	for _, f := range r.Findings {
		if !f.Waived {
			w += weights[f.Severity]
		}
	}
	return w
}

// Verify decides whether a proposed change (typically written by an LLM) is
// kept: it must not break apply, must not introduce any new medium-or-worse
// finding, and must lower the risk weight. The engine, not the model, decides.
func Verify(before, after *Report) (bool, string) {
	if after.Verdict.Blocking > before.Verdict.Blocking {
		return false, "rejected: the change would make terraform apply fail"
	}
	had := map[string]bool{}
	for _, f := range before.Findings {
		if !f.Waived {
			had[f.RuleID+"|"+f.Resource] = true
		}
	}
	added := 0
	for _, f := range after.Findings {
		if !f.Waived && f.Severity.Rank() >= Medium.Rank() && !had[f.RuleID+"|"+f.Resource] {
			added++
		}
	}
	if added > 0 {
		return false, fmt.Sprintf("rejected: introduces %d new medium-or-higher finding(s)", added)
	}
	b, a := RiskWeight(before), RiskWeight(after)
	if a >= b {
		return false, "rejected: no measurable improvement"
	}
	return true, fmt.Sprintf("accepted: risk weight %d to %d", b, a)
}
