package vuln

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		eco, a, b string
		want      int
	}{
		{"npm", "1.0.0", "1.0.0", 0},
		{"npm", "1.0.0-alpha", "1.0.0", -1},
		{"npm", "1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"npm", "1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"npm", "1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"npm", "1.0.0-rc.1", "1.0.0", -1},
		{"npm", "1.0.0+build", "1.0.0", 0},
		{"npm", "4.17.15", "4.17.21", -1},
		{"npm", "10.0.0", "9.9.9", 1},
		{"Go", "v1.2.3", "1.2.3", 0},
		{"Go", "0.0.0-20200101000000-abcdef", "0.0.1", -1},
		{"crates.io", "0.10.0", "0.9.0", 1},
		{"PyPI", "1.0", "1.0.0", 0},
		{"PyPI", "1.0.dev1", "1.0a1", -1},
		{"PyPI", "1.0a1", "1.0b1", -1},
		{"PyPI", "1.0rc1", "1.0", -1},
		{"PyPI", "1.0", "1.0.post1", -1},
		{"PyPI", "1.0.post1.dev1", "1.0.post1", -1},
		{"PyPI", "1.0-1", "1.0.post1", 0},
		{"PyPI", "1!0.1", "2.0", 1},
		{"PyPI", "2.0.0", "10.0", -1},
		{"PyPI", "1.0+local", "1.0", 0},
		{"PyPI", "1.0alpha1", "1.0a1", 0},
		{"Debian:12", "1:1.0", "2.0", 1},
		{"Debian:12", "1.0~rc1", "1.0", -1},
		{"Debian:12", "1.0~~", "1.0~", -1},
		{"Debian:12", "1.0-1", "1.0-1+deb12u1", -1},
		{"Debian:12", "3.0.11-1~deb12u2", "3.0.11-1", -1},
		{"Debian:12", "2.36-9+deb12u3", "2.36-9+deb12u4", -1},
		{"Ubuntu:22.04", "1.2.3-1ubuntu1", "1.2.3-1ubuntu1.1", -1},
		{"Debian:12", "1.0a", "1.0", 1},
		{"Alpine:v3.19", "1.2.3-r0", "1.2.3-r1", -1},
		{"Alpine:v3.19", "1.2.3_rc1-r0", "1.2.3-r0", -1},
		{"Alpine:v3.19", "1.2.3_p1-r0", "1.2.3-r0", 1},
		{"Alpine:v3.19", "1.2.3a-r0", "1.2.3-r0", 1},
		{"Alpine:v3.19", "3.1.4-r5", "3.1.10-r0", -1},
		{"Maven", "1.0-alpha", "1.0", -1},
		{"Maven", "1.0", "1.0.0", 0},
		{"Maven", "1.0-SNAPSHOT", "1.0", -1},
		{"Maven", "2.17.0", "2.15.0", 1},
		{"Maven", "1.0.Final", "1.0", 0},
		{"RubyGems", "1.0.0.rc1", "1.0.0", -1},
		{"RubyGems", "1.13.10", "1.13.9", 1},
		{"NuGet", "13.0.1", "13.0.3", -1},
		{"Packagist", "5.4.0", "v5.4.0", 0},
	}
	for _, c := range cases {
		got := Compare(c.eco, c.a, c.b)
		if sign(got) != c.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d", c.eco, c.a, c.b, got, c.want)
		}
		if back := Compare(c.eco, c.b, c.a); sign(back) != -c.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d", c.eco, c.b, c.a, back, -c.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestAffects(t *testing.T) {
	e := Entry{ID: "X", Ranges: []Range{
		{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "4.17.21"}}},
		{Type: "ECOSYSTEM", Events: []Event{{Fixed: "6.0.2"}, {Introduced: "6.0.0"}}}, // unsorted on purpose
		{Type: "GIT", Events: []Event{{Introduced: "0"}}},
	}, Versions: []string{"5.0.0-weird"}}
	for v, want := range map[string]bool{"4.17.15": true, "4.17.21": false, "5.0.0": false, "5.0.0-weird": true, "6.0.1": true, "6.0.2": false} {
		if got, _ := e.Affects("npm", v); got != want {
			t.Errorf("Affects(%s) = %v, want %v", v, got, want)
		}
	}
	if _, fixed := e.Affects("npm", "4.17.15"); fixed != "4.17.21" {
		t.Errorf("fixed = %q", fixed)
	}
	last := Entry{Ranges: []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0"}, {LastAffected: "1.5"}}}}}
	for v, want := range map[string]bool{"0.9": false, "1.0": true, "1.5": true, "1.5.1": false} {
		if got, _ := last.Affects("PyPI", v); got != want {
			t.Errorf("last_affected %s = %v, want %v", v, got, want)
		}
	}
}

func TestSeverity(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		if got, ok := cvss3(v); !ok || got != want {
			t.Errorf("cvss3(%s) = %v %v, want %v", v, got, ok, want)
		}
	}
	rec := &osvRecord{}
	rec.Affected = make([]struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Severity []osvSeverity `json:"severity"`
		Ranges   []Range       `json:"ranges"`
		Versions []string      `json:"versions"`
	}, 1)
	if s := severityOf(rec, 0); s != "UNKNOWN" {
		t.Errorf("no data: %s", s)
	}
	rec.Severity = []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	if s := severityOf(rec, 0); s != "CRITICAL" {
		t.Errorf("cvss: %s", s)
	}
	rec.DatabaseSpecific.Severity = "MODERATE"
	if s := severityOf(rec, 0); s != "MEDIUM" {
		t.Errorf("database_specific: %s", s)
	}
}
