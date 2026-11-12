package vuln

import (
	"strconv"
	"strings"
)

// Compare orders two versions by the rules of an OSV ecosystem: <0, 0 or >0.
func Compare(ecosystem, a, b string) int {
	switch baseEcosystem(ecosystem) {
	case "npm", "crates.io", "Go":
		return compareSemver(a, b)
	case "PyPI":
		return comparePEP440(a, b)
	case "Debian", "Ubuntu":
		return compareDpkg(a, b)
	case "Alpine":
		return compareApk(a, b)
	case "Red Hat", "Rocky Linux", "AlmaLinux", "Mageia", "Azure Linux", "openSUSE", "SUSE", "openEuler":
		return compareRPM(a, b)
	default:
		return compareGeneric(a, b)
	}
}

func baseEcosystem(e string) string {
	if i := strings.IndexByte(e, ':'); i >= 0 {
		return e[:i]
	}
	return e
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpNum compares digit strings of any length without overflow.
func cmpNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := cmpInt(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// --- semver 2.0 ---

type semver struct {
	core []string
	pre  []string
}

func parseSemver(v string) (semver, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, _, _ = strings.Cut(v, "+")
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, false
	}
	for _, p := range parts {
		if !allDigits(p) {
			return semver{}, false
		}
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	s := semver{core: parts}
	if hasPre {
		s.pre = strings.Split(pre, ".")
	}
	return s, true
}

func compareSemver(a, b string) int {
	x, ok1 := parseSemver(a)
	y, ok2 := parseSemver(b)
	if !ok1 || !ok2 {
		return compareGeneric(a, b)
	}
	for i := range 3 {
		if c := cmpNum(x.core[i], y.core[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0
	case len(x.pre) == 0:
		return 1
	case len(y.pre) == 0:
		return -1
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		p, q := x.pre[i], y.pre[i]
		pn, qn := allDigits(p), allDigits(q)
		var c int
		switch {
		case pn && qn:
			c = cmpNum(p, q)
		case pn:
			c = -1
		case qn:
			c = 1
		default:
			c = strings.Compare(p, q)
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(len(x.pre), len(y.pre))
}

// --- generic (Maven, RubyGems, NuGet, Packagist and anything else) ---

// shortcut: one tokenizer for Maven, RubyGems, NuGet and Packagist; covers
// numeric parts and pre-release words, not every qualifier rule of each tool.
func tokens(v string) []string {
	v = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	v, _, _ = strings.Cut(v, "+")
	var out []string
	cur := ""
	flush := func() {
		if cur != "" {
			out = append(out, cur)
			cur = ""
		}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.' || c == '-' || c == '_':
			flush()
		case cur != "" && isDigit(c) != isDigit(cur[0]):
			flush()
			cur = string(c)
		default:
			cur += string(c)
		}
	}
	flush()
	// Trailing zeros and release words do not change a version: 1.0 == 1.0.0 == 1.0-final.
	for len(out) > 0 {
		last := out[len(out)-1]
		if strings.TrimLeft(last, "0") == "" || releaseWords[last] {
			out = out[:len(out)-1]
			continue
		}
		break
	}
	return out
}

var releaseWords = map[string]bool{"final": true, "ga": true, "release": true, "r": true}

var preWords = map[string]int{"dev": 1, "snapshot": 1, "alpha": 2, "a": 2, "beta": 3, "b": 3, "milestone": 4, "m": 4, "pre": 5, "preview": 5, "rc": 6, "cr": 6}

// wordRank places pre-release words below a release (negative) and others above.
func wordRank(w string) int {
	if r, ok := preWords[w]; ok {
		return r - 10
	}
	return 1
}

func compareGeneric(a, b string) int {
	x, y := tokens(a), tokens(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		p, q := "0", "0" // a missing part reads as zero: 1.0 == 1.0.0
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		switch {
		case i >= len(x) && !allDigits(q):
			return -sideRank(q)
		case i >= len(y) && !allDigits(p):
			return sideRank(p)
		}
		pn, qn := allDigits(p), allDigits(q)
		var c int
		switch {
		case pn && qn:
			c = cmpNum(p, q)
		case pn:
			c = 1 // 1.1 > 1.alpha
		case qn:
			c = -1
		default:
			if c = cmpInt(wordRank(p), wordRank(q)); c == 0 {
				c = strings.Compare(p, q)
			}
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

// sideRank says whether an extra word makes a version newer (+1) or older (-1).
func sideRank(t string) int {
	if wordRank(t) < 0 {
		return -1
	}
	return 1
}

// --- PEP 440 ---

type pep440 struct {
	epoch   int
	release []string
	preL    int // -2 dev-only, -1..: a=0 b=1 rc=2, 3 none
	preN    string
	post    string // "" none
	dev     string // "" none
	hasPost bool
	hasDev  bool
}

var pepPre = map[string]int{"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}

func parsePEP440(v string) pep440 {
	v = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "v"))
	v, _, _ = strings.Cut(v, "+") // local versions do not affect ordering against public ones
	var p pep440
	if e, rest, ok := strings.Cut(v, "!"); ok {
		p.epoch, _ = strconv.Atoi(e)
		v = rest
	}
	i := 0
	for i < len(v) && (isDigit(v[i]) || v[i] == '.') {
		i++
	}
	for _, r := range strings.Split(strings.Trim(v[:i], "."), ".") {
		if r != "" {
			p.release = append(p.release, r)
		}
	}
	for len(p.release) > 1 && strings.TrimLeft(p.release[len(p.release)-1], "0") == "" {
		p.release = p.release[:len(p.release)-1]
	}
	p.preL = 3
	rest := v[i:]
parts:
	for rest != "" {
		rest = strings.TrimLeft(rest, ".-_")
		word := leading(rest, func(c byte) bool { return c >= 'a' && c <= 'z' })
		rest = strings.TrimLeft(rest[len(word):], ".-_")
		num := leading(rest, isDigit)
		rest = rest[len(num):]
		if word == "" && num == "" {
			break parts // unparsable tail
		}
		if num == "" {
			num = "0"
		}
		switch {
		case word == "": // "1.0-1" is a post release
			p.post, p.hasPost = num, true
		case hasKey(pepPre, word):
			p.preL, p.preN = pepPre[word], num
		case word == "post" || word == "rev" || word == "r":
			p.post, p.hasPost = num, true
		case word == "dev":
			p.dev, p.hasDev = num, true
		default:
			break parts
		}
	}
	if p.preL == 3 && !p.hasPost && p.hasDev {
		p.preL = -2 // 1.0.dev1 sorts before 1.0a1
	}
	return p
}

func hasKey(m map[string]int, k string) bool { _, ok := m[k]; return ok }

func leading(s string, ok func(byte) bool) string {
	i := 0
	for i < len(s) && ok(s[i]) {
		i++
	}
	return s[:i]
}

func comparePEP440(a, b string) int {
	x, y := parsePEP440(a), parsePEP440(b)
	if c := cmpInt(x.epoch, y.epoch); c != 0 {
		return c
	}
	for i := 0; i < len(x.release) || i < len(y.release); i++ {
		p, q := "0", "0"
		if i < len(x.release) {
			p = x.release[i]
		}
		if i < len(y.release) {
			q = y.release[i]
		}
		if c := cmpNum(p, q); c != 0 {
			return c
		}
	}
	if c := cmpInt(x.preL, y.preL); c != 0 {
		return c
	}
	if c := cmpNum(x.preN, y.preN); c != 0 {
		return c
	}
	if c := cmpOptional(x.hasPost, y.hasPost, x.post, y.post, -1); c != 0 {
		return c
	}
	return cmpOptional(x.hasDev, y.hasDev, x.dev, y.dev, 1)
}

// cmpOptional compares optional numbers; missing sorts as absent (-1 low, +1 high).
func cmpOptional(hx, hy bool, x, y string, absent int) int {
	switch {
	case !hx && !hy:
		return 0
	case !hx:
		return absent
	case !hy:
		return -absent
	}
	return cmpNum(x, y)
}

// --- dpkg (Debian, Ubuntu) ---

func compareDpkg(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if c := cmpNum(ea, eb); c != 0 {
		return c
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDpkg(v string) (epoch, upstream, revision string) {
	v = strings.TrimSpace(v)
	epoch = "0"
	if e, rest, ok := strings.Cut(v, ":"); ok && allDigits(e) {
		epoch, v = e, rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func dpkgOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's algorithm: alternate non-digit runs (with ~ lowest) and numbers.
func verrevcmp(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			ac, bc := 0, 0
			if a != "" {
				ac = dpkgOrder(a[0])
			}
			if b != "" {
				bc = dpkgOrder(b[0])
			}
			if ac != bc {
				return cmpInt(ac, bc)
			}
			a, b = a[1:], b[1:]
		}
		na, nb := leading(a, isDigit), leading(b, isDigit)
		if c := cmpNum(na, nb); c != 0 {
			return c
		}
		a, b = a[len(na):], b[len(nb):]
	}
	return 0
}

// --- apk (Alpine) ---

var apkSuffix = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

type apkVersion struct {
	nums     []string
	letter   byte
	suffixes [][2]string // name, number
	rev      string
}

func parseApk(v string) apkVersion {
	var p apkVersion
	v = strings.TrimSpace(v)
	if i := strings.LastIndex(v, "-r"); i >= 0 && allDigits(v[i+2:]) {
		p.rev, v = v[i+2:], v[:i]
	}
	main, suf, _ := strings.Cut(v, "_")
	if n := len(main); n > 0 && !isDigit(main[n-1]) && main[n-1] != '.' {
		p.letter, main = main[n-1], main[:n-1]
	}
	p.nums = strings.Split(main, ".")
	if suf != "" {
		for _, s := range strings.Split(suf, "_") {
			name := leading(s, func(c byte) bool { return !isDigit(c) })
			p.suffixes = append(p.suffixes, [2]string{name, s[len(name):]})
		}
	}
	return p
}

func compareApk(a, b string) int {
	x, y := parseApk(a), parseApk(b)
	for i := 0; i < len(x.nums) || i < len(y.nums); i++ {
		switch {
		case i >= len(x.nums):
			return -1
		case i >= len(y.nums):
			return 1
		}
		// apk compares later components as decimals unless one has a leading zero.
		if c := cmpNum(x.nums[i], y.nums[i]); c != 0 {
			return c
		}
	}
	if c := cmpInt(int(x.letter), int(y.letter)); c != 0 {
		return c
	}
	for i := 0; i < len(x.suffixes) || i < len(y.suffixes); i++ {
		var sx, sy int
		var nx, ny string
		if i < len(x.suffixes) {
			sx, nx = apkSuffix[x.suffixes[i][0]], x.suffixes[i][1]
		}
		if i < len(y.suffixes) {
			sy, ny = apkSuffix[y.suffixes[i][0]], y.suffixes[i][1]
		}
		if c := cmpInt(sx, sy); c != 0 {
			return c
		}
		if c := cmpNum(nx, ny); c != 0 {
			return c
		}
	}
	return cmpNum(x.rev, y.rev)
}
