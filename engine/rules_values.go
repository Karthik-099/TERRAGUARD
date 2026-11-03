package engine

//go:generate go run ../tools/awsvalgen -out values_aws_gen.go -mappings $TFLINT_AWS/rules/models/mappings -models $AWS_API_MODELS -schema $TFLINT_AWS/tools/provider-schema/schema.json

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// awsValueCheck is one argument constraint from the AWS API models.
type awsValueCheck struct {
	attr     string
	enum     []string
	pattern  string
	min, max int // length in characters
}

var awsPatterns sync.Map // pattern -> *regexp.Regexp

func awsPattern(p string) *regexp.Regexp {
	if re, ok := awsPatterns.Load(p); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(p) // the generator keeps only patterns that compile
	awsPatterns.Store(p, re)
	return re
}

func awsValueTypes() []string {
	out := make([]string, 0, len(awsValueChecks))
	for t := range awsValueChecks {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

var valueRules = []Rule{
	{ID: "TG-VAL-020", Title: "Value the AWS API rejects", Severity: High, Category: CatValidate, CWE: "CWE-20", Blocking: true,
		Types: awsValueTypes(), Remediation: "Use a value the AWS API accepts; plan succeeds but apply fails with a validation error.",
		Check: checkAWSValues},
}

func checkAWSValues(r *Resource) []Hit {
	if r.Mode == "data" || r.Format != "" {
		return nil
	}
	var hits []Hit
	for _, c := range awsValueChecks[r.Type] {
		v, ok := asString(r.Attrs[c.attr])
		if !ok || v == "" { // empty usually means unset
			continue
		}
		// Only a whole-value enum check is safe when the value is built from a variable
		// (a module default like "" glued to a suffix), or is a document the provider
		// normalizes (JSON, heredoc) before sending it.
		if t := strings.TrimSpace(v); r.via(c.attr) != "" || strings.ContainsAny(v, "\r\n") || strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
			c = awsValueCheck{attr: c.attr, enum: c.enum}
		}
		if msg := c.problem(v); msg != "" {
			hits = append(hits, Hit{Path: c.attr, Msg: fmt.Sprintf("%s = %q: %s; AWS rejects it during apply.", c.attr, v, msg)})
		}
	}
	return hits
}

func (c awsValueCheck) problem(v string) string {
	if c.enum != nil {
		// Case-insensitive: the provider upper-cases some arguments (lb protocol) before sending.
		if slices.ContainsFunc(c.enum, func(e string) bool { return strings.EqualFold(e, v) }) {
			return ""
		}
		msg := "not an allowed value"
		if s := closest(v, c.enum); s != "" {
			msg += fmt.Sprintf(" (did you mean %q?)", s)
		}
		shown := c.enum
		if len(shown) > 8 {
			shown = shown[:8]
		}
		msg += "; allowed: " + strings.Join(shown, ", ")
		if len(c.enum) > len(shown) {
			msg += fmt.Sprintf(" and %d more", len(c.enum)-len(shown))
		}
		return msg
	}
	n := utf8.RuneCountInString(v)
	if c.max > 0 && n > c.max {
		return fmt.Sprintf("%d characters, longer than the maximum of %d", n, c.max)
	}
	if n < c.min {
		return fmt.Sprintf("%d characters, shorter than the minimum of %d", n, c.min)
	}
	if c.pattern != "" && !awsPattern(c.pattern).MatchString(v) {
		return fmt.Sprintf("does not match the pattern %s", c.pattern)
	}
	return ""
}

// closest returns the candidate within edit distance 2 of v, if any.
func closest(v string, cands []string) string {
	best, bestD := "", 3
	for _, c := range cands {
		if d := editDistance(v, c); d < bestD {
			best, bestD = c, d
		}
	}
	return best
}
