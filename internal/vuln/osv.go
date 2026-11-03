package vuln

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

// osvRecord is the subset of the OSV schema (ossf.github.io/osv-schema) used here.
type osvRecord struct {
	ID               string        `json:"id"`
	Summary          string        `json:"summary"`
	Details          string        `json:"details"`
	Aliases          []string      `json:"aliases"`
	Withdrawn        string        `json:"withdrawn"`
	Severity         []osvSeverity `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Severity []osvSeverity `json:"severity"`
		Ranges   []Range       `json:"ranges"`
		Versions []string      `json:"versions"`
	} `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Range is an OSV affected range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Entry is what the index keeps for one vulnerability of one package.
type Entry struct {
	ID       string
	Aliases  []string
	Summary  string
	Severity string
	Ranges   []Range
	Versions []string
}

// Affects reports whether version is affected, and the lowest fixed version above it.
func (e Entry) Affects(ecosystem, version string) (bool, string) {
	hit := false
	for _, v := range e.Versions {
		if v == version {
			hit = true
		}
	}
	fixed := ""
	for _, r := range e.Ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue // GIT ranges name commits, not versions
		}
		if inRange(ecosystem, version, r.Events) {
			hit = true
			if f := nextFixed(ecosystem, version, r.Events); f != "" && (fixed == "" || Compare(ecosystem, f, fixed) < 0) {
				fixed = f
			}
		}
	}
	return hit, fixed
}

func eventVersion(e Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return e.Limit
}

// inRange replays the events in version order, as the OSV spec describes.
func inRange(eco, v string, events []Event) bool {
	evs := append([]Event(nil), events...)
	sort.SliceStable(evs, func(i, j int) bool {
		return cmpEvent(eco, eventVersion(evs[i]), eventVersion(evs[j])) < 0
	})
	affected := false
	for _, e := range evs {
		ev := eventVersion(e)
		c := cmpEvent(eco, v, ev)
		switch {
		case e.Introduced != "" && c >= 0:
			affected = true
		case e.Fixed != "" && c >= 0, e.Limit != "" && c >= 0, e.LastAffected != "" && c > 0:
			affected = false
		}
	}
	return affected
}

// cmpEvent treats "0" as below every version.
func cmpEvent(eco, a, b string) int {
	switch {
	case a == b:
		return 0
	case b == "0":
		return 1
	case a == "0":
		return -1
	}
	return Compare(eco, a, b)
}

func nextFixed(eco, v string, events []Event) string {
	best := ""
	for _, e := range events {
		if e.Fixed != "" && Compare(eco, e.Fixed, v) > 0 && (best == "" || Compare(eco, e.Fixed, best) < 0) {
			best = e.Fixed
		}
	}
	return best
}

// severityOf picks the database's own rating, then a CVSS v3 score, then a textual rating.
func severityOf(r *osvRecord, i int) string {
	if s := normSeverity(r.DatabaseSpecific.Severity); s != "" {
		return s
	}
	all := append(append([]osvSeverity(nil), r.Severity...), r.Affected[i].Severity...)
	for _, s := range all {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			if score, ok := cvss3(s.Score); ok {
				return scoreSeverity(score)
			}
		}
	}
	for _, s := range all {
		if v := normSeverity(s.Score); v != "" {
			return v // e.g. Ubuntu's "medium"
		}
	}
	return "UNKNOWN"
}

func normSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH", "IMPORTANT":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MEDIUM"
	case "LOW", "NEGLIGIBLE":
		return "LOW"
	}
	return ""
}

func scoreSeverity(s float64) string {
	switch {
	case s >= 9:
		return "CRITICAL"
	case s >= 7:
		return "HIGH"
	case s >= 4:
		return "MEDIUM"
	}
	return "LOW"
}

var cvssWeights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// cvss3 computes the CVSS v3.x base score from a vector string.
func cvss3(vector string) (float64, bool) {
	if f, err := strconv.ParseFloat(vector, 64); err == nil {
		return f, true // some sources store the number itself
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	changed := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr["L"], pr["H"] = 0.68, 0.5
	}
	w := map[string]float64{}
	for k, table := range cvssWeights {
		v, ok := table[m[k]]
		if !ok {
			return 0, false
		}
		w[k] = v
	}
	prw, ok := pr[m["PR"]]
	if !ok {
		return 0, false
	}
	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploit := 8.22 * w["AV"] * w["AC"] * prw * w["UI"]
	base := impact + exploit
	if changed {
		base *= 1.08
	}
	return roundUp(math.Min(base, 10)), true
}

// roundUp is the CVSS 3.1 "round up to one decimal" that avoids float noise.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
