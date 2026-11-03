package engine

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Rules for Dockerfiles (resource shapes in format_dockerfile.go).

func init() { registerForeign(dockerForeign) }

// registerForeign maps reference check IDs to the rules that cover them.
func registerForeign(foreign map[string][]string) {
	for ref, ids := range foreign {
		foreignRules[ref] = append(foreignRules[ref], ids...)
	}
}

var dockerForeign = map[string][]string{
	"CKV_DOCKER_1": {"TG-DOCKER-EXPOSE-001"}, "CKV_DOCKER_2": {"TG-DOCKER-HEALTH-001"}, "CKV_DOCKER_3": {"TG-DOCKER-USER-001"},
	"CKV_DOCKER_4": {"TG-DOCKER-ADD-001", "TG-DOCKER-ADD-002"}, "CKV_DOCKER_5": {"TG-DOCKER-RUN-002"}, "CKV_DOCKER_6": {"TG-DOCKER-MAINT-001"},
	"CKV_DOCKER_7": {"TG-DOCKER-FROM-001"}, "CKV_DOCKER_8": {"TG-DOCKER-USER-002"}, "CKV_DOCKER_9": {"TG-DOCKER-RUN-001"},
	"CKV_DOCKER_10": {"TG-DOCKER-WORKDIR-001"}, "CKV_DOCKER_11": {"TG-DOCKER-FROM-003"},
	"CKV2_DOCKER_1": {"TG-DOCKER-RUN-003"}, "CKV2_DOCKER_2": {"TG-DOCKER-TLS-001"}, "CKV2_DOCKER_3": {"TG-DOCKER-TLS-001"},
	"CKV2_DOCKER_4": {"TG-DOCKER-TLS-001"}, "CKV2_DOCKER_5": {"TG-DOCKER-TLS-001"}, "CKV2_DOCKER_6": {"TG-DOCKER-TLS-001"},
	"CKV2_DOCKER_7": {"TG-DOCKER-PKG-001"}, "CKV2_DOCKER_8": {"TG-DOCKER-PKG-001"}, "CKV2_DOCKER_9": {"TG-DOCKER-PKG-001"},
	"CKV2_DOCKER_10": {"TG-DOCKER-PKG-001"}, "CKV2_DOCKER_11": {"TG-DOCKER-PKG-001"}, "CKV2_DOCKER_12": {"TG-DOCKER-TLS-001"},
	"CKV2_DOCKER_13": {"TG-DOCKER-TLS-001"}, "CKV2_DOCKER_14": {"TG-DOCKER-TLS-001"}, "CKV2_DOCKER_15": {"TG-DOCKER-TLS-001"},
	"CKV2_DOCKER_16": {"TG-DOCKER-TLS-001"}, "CKV2_DOCKER_17": {"TG-DOCKER-RUN-005"},
}

// dkIns is one instruction read back from a resource's Attrs.
type dkIns struct {
	cmd, value  string
	flags, args []string
	json        bool
	idx         int
}

func (d dkIns) path() string { return "instructions." + strconv.Itoa(d.idx) }

func (d dkIns) flag(name string) (string, bool) {
	for _, f := range d.flags {
		if v, ok := strings.CutPrefix(f, name+"="); ok {
			return v, true
		}
		if f == name {
			return "", true
		}
	}
	return "", false
}

// shell is the command text of a RUN, CMD or ENTRYPOINT.
func (d dkIns) shell() string {
	if d.json {
		return strings.Join(d.args, " ")
	}
	return d.value
}

func dkInstrs(a map[string]any) []dkIns {
	var out []dkIns
	for i, e := range asList(a["instructions"]) {
		m, _ := e.(map[string]any)
		cmd, _ := m["cmd"].(string)
		val, _ := m["value"].(string)
		j, _ := m["json"].(bool)
		out = append(out, dkIns{cmd: cmd, value: val, flags: asStrings(m["flags"]), args: asStrings(m["args"]), json: j, idx: i})
	}
	return out
}

func dkStages(r *Resource) []map[string]any {
	var out []map[string]any
	for _, s := range asList(r.Attrs["stages"]) {
		if m, ok := s.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// dkChain lists the final stage and the stages it builds on, nearest first.
func dkChain(r *Resource) []int {
	st := dkStages(r)
	var out []int
	for i := len(st) - 1; i >= 0 && len(out) <= len(st); {
		out = append(out, i)
		p, _ := asFloat(st[i]["parent"])
		if int(p) >= i {
			break
		}
		i = int(p)
	}
	return out
}

var dkSplitRE = regexp.MustCompile(`&&|\|\||[;|\n()]`)

// dkCommands splits shell text into simple commands, each as words.
func dkCommands(text string) [][]string {
	var out [][]string
	for _, part := range dkSplitRE.Split(text, -1) {
		if w := dockerWords(part); len(w) > 0 {
			out = append(out, w)
		}
	}
	return out
}

// dkStrip drops leading variable assignments and sudo.
func dkStrip(w []string) []string {
	for len(w) > 0 {
		switch {
		case strings.Contains(w[0], "=") && !strings.HasPrefix(w[0], "-"):
			w = w[1:]
		case w[0] == "sudo" || w[0] == "exec" || w[0] == "command":
			w = w[1:]
			for len(w) > 0 && strings.HasPrefix(w[0], "-") {
				w = w[1:]
			}
		default:
			return w
		}
	}
	return w
}

type dkPkg struct {
	mgr              string
	pre, flags, pkgs []string
}

var dkPkgSub = map[string][]string{
	"apt-get": {"install"}, "apt": {"install"}, "apk": {"add"}, "yum": {"install"}, "dnf": {"install"}, "tdnf": {"install"},
	"microdnf": {"install"}, "zypper": {"install", "in"}, "pip": {"install"}, "npm": {"install", "i", "add"}, "yarn": {"add"},
	"gem": {"install"},
}

// dkValueFlags take the next word as their value.
var dkValueFlags = map[string]bool{"-o": true, "-t": true, "-r": true, "-c": true, "-e": true, "-i": true, "-X": true,
	"--repository": true, "--virtual": true, "--index-url": true, "--extra-index-url": true, "--requirement": true,
	"--constraint": true, "--target": true, "--trusted-host": true, "--prefix": true, "--root": true, "-f": true,
	"--find-links": true, "--setopt": true, "--enablerepo": true, "--disablerepo": true, "-v": true, "--version": true,
	"--registry": true, "--install-dir": true}

// dkInstall recognises a package install command.
func dkInstall(w []string) (dkPkg, bool) {
	w = dkStrip(w)
	if len(w) > 2 && strings.HasPrefix(w[0], "python") && w[1] == "-m" {
		w = w[2:]
	}
	if len(w) == 0 {
		return dkPkg{}, false
	}
	mgr := path.Base(w[0])
	if strings.HasPrefix(mgr, "pip") {
		mgr = "pip"
	}
	subs, ok := dkPkgSub[mgr]
	if !ok {
		return dkPkg{}, false
	}
	p := dkPkg{mgr: mgr}
	i := 1
	for ; i < len(w) && strings.HasPrefix(w[i], "-"); i++ {
		p.pre = append(p.pre, w[i])
	}
	if i >= len(w) || !contains(subs, w[i]) {
		return dkPkg{}, false
	}
	for i++; i < len(w); i++ {
		if strings.HasPrefix(w[i], "-") {
			p.flags = append(p.flags, w[i])
			if dkValueFlags[w[i]] && i+1 < len(w) {
				i++
				p.flags = append(p.flags, w[i])
			}
			continue
		}
		p.pkgs = append(p.pkgs, w[i])
	}
	return p, true
}

func (p dkPkg) has(flags ...string) bool {
	return contains(p.pre, flags...) || contains(p.flags, flags...)
}

var dkRPMVersionRE = regexp.MustCompile(`-\d`)

func dkPinned(p dkPkg, pkg string) bool {
	low := strings.ToLower(pkg)
	if strings.ContainsAny(pkg, "$*/") || strings.HasPrefix(pkg, ".") || strings.Contains(pkg, "://") || strings.HasPrefix(pkg, "@") && p.mgr != "npm" && p.mgr != "yarn" {
		return true
	}
	for _, ext := range []string{".deb", ".rpm", ".whl", ".tar.gz", ".tgz", ".zip", ".apk", ".gem"} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	switch p.mgr {
	case "pip":
		return strings.Contains(pkg, "==") || strings.Contains(pkg, "~=") || strings.Contains(pkg, "@")
	case "npm", "yarn":
		return strings.LastIndex(pkg, "@") > 0
	case "gem":
		return strings.Contains(pkg, ":") || p.has("-v", "--version")
	case "yum", "dnf", "tdnf", "microdnf":
		return dkRPMVersionRE.MatchString(pkg) || strings.ContainsAny(pkg, "=<>")
	}
	return strings.ContainsAny(pkg, "=<>")
}

func dkAssumeYes(p dkPkg) bool {
	for _, f := range append(append([]string{}, p.pre...), p.flags...) {
		switch f {
		case "--yes", "--assume-yes", "--assumeyes", "--non-interactive", "--no-confirm", "--force-yes":
			return true
		}
		if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") {
			if strings.Contains(f, "y") || strings.Contains(f, "qq") || p.mgr == "zypper" && strings.Contains(f, "n") {
				return true
			}
		}
	}
	return false
}

// Shared text matchers, also used by the CI rules.
var (
	pipeShellRE = regexp.MustCompile(`(?:\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/usr)?(?:/bin/)?(?:ba|z|da|k|a)?sh\b)|(?:\b(?:ba|z)?sh\s+(?:-c\s+)?["']?(?:\$\(|<\()\s*(?:curl|wget)\b)`)
	tlsOffREs   = []*regexp.Regexp{
		regexp.MustCompile(`\bcurl\b[^|&;\n]*\s(?:--insecure\b|-[^-\s]*k)`),
		regexp.MustCompile(`\bwget\b[^|&;\n]*\s--no-check-certificate`),
		regexp.MustCompile(`\bpip3?\b[^|&;\n]*\s--trusted-host`),
		regexp.MustCompile(`\b(?:npm|yarn)\s+(?:c(?:onfig)?\s+)?set\s+["']?strict-ssl["']?(?:\s+|=)["']?false`),
		regexp.MustCompile(`(?i)\b(?:yum|dnf)(?:\s+|-)config-manager[^|&;\n]*--setopt=["']?(?:[^=\s]+\.)?sslverify["']?=["']?(?:0|false|no)\b`),
		regexp.MustCompile(`(?i)\bgit\b[^|&;\n]*http\.sslverify[= ]+["']?false`),
		regexp.MustCompile(`(?:^|[\s;&|'"])(?:export\s+)?(?:GIT_SSL_NO_VERIFY=\S+|NODE_TLS_REJECT_UNAUTHORIZED=["']?0\b|PYTHONHTTPSVERIFY=["']?0\b|(?i:npm_config_strict_ssl)=["']?false|PIP_TRUSTED_HOST=\S+)`),
	}
	unsignedREs = []*regexp.Regexp{
		regexp.MustCompile(`\bapk\b[^|&;\n]*\s--allow-untrusted`),
		regexp.MustCompile(`\bapt(?:-get)?\b[^|&;\n]*\s(?:--allow-unauthenticated|--force-yes|--allow-insecure-repositories)`),
		regexp.MustCompile(`\b(?:t?dnf|yum|microdnf)\b[^|&;\n]*\s--nogpgcheck`),
		regexp.MustCompile(`\brpm\b[^|&;\n]*\s--no(?:digest|signature|verify|filedigest)`),
		regexp.MustCompile(`\[[^\]]*trusted=yes[^\]]*\]`),
	}
	netcatRE   = regexp.MustCompile(`\b(?:nc|ncat|netcat)\b(?:\s+-\S+)*\s+\d{1,3}(?:\.\d{1,3}){3}\b`)
	ncProbeRE  = regexp.MustCompile(`\s-\S*z|\s127\.`)
	dkUpdateRE = regexp.MustCompile(`^(?:--)?update$`)
	dkSecretRE = regexp.MustCompile(`(?i)(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.env|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.htpasswd|kubeconfig|[^/]*\.pem|[^/]*\.key|[^/]*\.p12|[^/]*\.pfx)$|(^|/)\.(aws|ssh|kube)(/|$)|\.docker/config\.json$`)
	dkAbsRE    = regexp.MustCompile(`^["']?(/|\$|[A-Za-z]:[\\/])`)
	dkArchive  = regexp.MustCompile(`(?i)\.(tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|tar\.zst)$`)
)

func tlsOffText(s string) bool {
	for _, re := range tlsOffREs {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func tlsOffEnv(k, v string) bool {
	v = strings.Trim(v, `"'`)
	switch strings.ToUpper(k) {
	case "GIT_SSL_NO_VERIFY", "PIP_TRUSTED_HOST":
		return v != ""
	case "NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY":
		return v == "0"
	case "NPM_CONFIG_STRICT_SSL":
		return strings.EqualFold(v, "false")
	}
	return false
}

// literalSecret reports a secret-looking name set to a literal value.
func literalSecret(k string, v any) bool {
	s, ok := v.(string)
	return ok && secretAttrRE.MatchString(k) && strings.TrimSpace(s) != "" && !strings.ContainsAny(s, "$<{(") &&
		!strings.EqualFold(s, "true") && !strings.EqualFold(s, "false")
}

// imageRef classifies an image reference: "var", "digest", "latest" (or no tag) or "tag".
func imageRef(img string) string {
	img = strings.TrimSpace(img)
	switch {
	case img == "" || strings.ContainsAny(img, "$<{"):
		return "var"
	case strings.Contains(img, "@"):
		return "digest"
	}
	last := img[strings.LastIndex(img, "/")+1:]
	_, tag, ok := strings.Cut(last, ":")
	if !ok || tag == "latest" {
		return "latest"
	}
	return "tag"
}

func dkRoot(u string) bool {
	u = strings.ToLower(strings.TrimSpace(u))
	name, _, _ := strings.Cut(u, ":")
	return name == "root" || name == "0"
}

func dkRun(r *Resource, fn func(d dkIns, text string) []Hit) []Hit {
	var out []Hit
	for _, d := range dkInstrs(r.Attrs) {
		if d.cmd == "RUN" {
			out = append(out, fn(d, d.shell())...)
		}
	}
	return out
}

func dkEach(r *Resource, cmd string, fn func(d dkIns) []Hit) []Hit {
	var out []Hit
	for _, d := range dkInstrs(r.Attrs) {
		if d.cmd == cmd {
			out = append(out, fn(d)...)
		}
	}
	return out
}

func dkCommandsRun(r *Resource, fn func(d dkIns, w []string) *Hit) []Hit {
	return dkRun(r, func(d dkIns, text string) []Hit {
		for _, w := range dkCommands(text) {
			if h := fn(d, w); h != nil {
				return []Hit{*h}
			}
		}
		return nil
	})
}

func dkHit(d dkIns, msg string) *Hit { return &Hit{Path: d.path(), Msg: msg} }

var (
	stageT = []string{"dockerfile_stage"}
	fileT  = []string{"dockerfile"}
	bothT  = []string{"dockerfile_stage", "dockerfile"}
)

var dockerRules = []Rule{
	{ID: "TG-DOCKER-FROM-001", Title: "Base image uses the latest tag or no tag", Severity: Medium, Category: CatSecurity, CWE: "CWE-1357", Types: stageT,
		Remediation: "Pin the base image to a version tag, ideally with a digest (image:1.2.3@sha256:...).",
		Check: func(r *Resource) []Hit {
			base, _ := r.Attrs["base"].(string)
			p, _ := asFloat(r.Attrs["parent"])
			if p >= 0 || strings.EqualFold(base, "scratch") || base == "" {
				return nil
			}
			if imageRef(base) == "latest" || strings.HasSuffix(base, ":latest") {
				return []Hit{{Path: "base", Msg: "Builds pull whatever " + base + " points to that day, so the image changes without a code change."}}
			}
			return nil
		}},
	{ID: "TG-DOCKER-FROM-002", Title: "Base image is not pinned by digest", Severity: Low, Category: CatSecurity, CWE: "CWE-1357", Types: stageT,
		Remediation: "Add the digest to the base image (image:1.2.3@sha256:...) and update it with a dependency bot.",
		Check: func(r *Resource) []Hit {
			base, _ := r.Attrs["base"].(string)
			p, _ := asFloat(r.Attrs["parent"])
			if p < 0 && imageRef(base) == "tag" {
				return []Hit{{Path: "base", Msg: "A tag can be moved to a different image; " + base + " is trusted without a content hash."}}
			}
			return nil
		}},
	{ID: "TG-DOCKER-FROM-003", Title: "Two build stages share a name", Severity: Low, Category: CatReliability, Types: fileT,
		Remediation: "Give every FROM ... AS stage a unique name.",
		Check: func(r *Resource) []Hit {
			seen := map[string]bool{}
			var out []Hit
			for i, s := range dkStages(r) {
				n, _ := s["name"].(string)
				n = strings.ToLower(n)
				if n != "" && seen[n] {
					out = append(out, Hit{Path: "stages." + strconv.Itoa(i) + ".name", Msg: "Stage name " + n + " is used twice, so COPY --from and --target pick an unexpected stage."})
				}
				seen[n] = true
			}
			return out
		}},
	{ID: "TG-DOCKER-FROM-004", Title: "FROM forces a fixed platform", Severity: Info, Category: CatBestPrac, Types: stageT,
		Remediation: "Drop --platform or use $BUILDPLATFORM/$TARGETPLATFORM so multi-platform builds work.",
		Check: func(r *Resource) []Hit {
			if p, _ := r.Attrs["platform"].(string); p != "" && !strings.Contains(p, "$") {
				return []Hit{{Path: "platform", Msg: "The stage always builds for " + p + ", whatever platform is requested."}}
			}
			return nil
		}},
	{ID: "TG-DOCKER-FROM-005", Title: "COPY --from refers to a stage by number", Severity: Low, Category: CatReliability, Types: stageT,
		Remediation: "Name the stage (FROM image AS builder) and use COPY --from=builder.",
		Check: func(r *Resource) []Hit {
			return dkEach(r, "COPY", func(d dkIns) []Hit {
				if v, ok := d.flag("--from"); ok && v != "" && strings.Trim(v, "0123456789") == "" {
					return []Hit{*dkHit(d, "Reordering stages silently changes what --from="+v+" copies.")}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-USER-001", Title: "Image runs as root because no USER is set", Severity: Medium, Category: CatSecurity, CWE: "CWE-250", Types: fileT,
		Remediation: "Create an unprivileged user and add USER <name> to the final stage.",
		Check: func(r *Resource) []Hit {
			st := dkStages(r)
			chain := dkChain(r)
			for _, i := range chain {
				if _, ok := st[i]["user"]; ok {
					return nil
				}
			}
			root := st[chain[len(chain)-1]]
			base, _ := root["base"].(string)
			lb := strings.ToLower(base)
			if lb == "scratch" || strings.Contains(lb, "nonroot") || strings.Contains(lb, "rootless") {
				return nil
			}
			return []Hit{{Path: "stages." + strconv.Itoa(chain[0]) + ".base", Msg: "Containers from this image run as root, so a compromised process controls the whole container."}}
		}},
	{ID: "TG-DOCKER-USER-002", Title: "Last USER is root", Severity: High, Category: CatSecurity, CWE: "CWE-250", Types: fileT,
		Remediation: "End the final stage with USER set to an unprivileged user.",
		Check: func(r *Resource) []Hit {
			st := dkStages(r)
			for _, i := range dkChain(r) {
				if u, ok := st[i]["user"].(string); ok {
					if dkRoot(u) {
						return []Hit{{Path: "stages." + strconv.Itoa(i) + ".user", Msg: "The container process runs as root, so a compromised process controls the whole container."}}
					}
					return nil
				}
			}
			return nil
		}},
	{ID: "TG-DOCKER-HEALTH-001", Title: "Image has no HEALTHCHECK", Severity: Low, Category: CatReliability, CWE: "CWE-754", Types: fileT,
		Remediation: "Add HEALTHCHECK CMD <probe> to the final stage (or HEALTHCHECK NONE when the orchestrator probes it).",
		Check: func(r *Resource) []Hit {
			st := dkStages(r)
			chain := dkChain(r)
			for _, i := range chain {
				for _, d := range dkInstrs(st[i]) {
					if d.cmd == "HEALTHCHECK" {
						return nil
					}
				}
			}
			return []Hit{{Path: "stages." + strconv.Itoa(chain[0]) + ".base", Msg: "Docker cannot tell a hung container from a healthy one, so it is never restarted."}}
		}},
	{ID: "TG-DOCKER-EXPOSE-001", Title: "Image exposes SSH port 22", Severity: Low, Category: CatSecurity, CWE: "CWE-284", Types: stageT,
		Remediation: "Remove port 22 from EXPOSE; use docker exec or kubectl exec instead of SSH.",
		Check: func(r *Resource) []Hit {
			return dkEach(r, "EXPOSE", func(d dkIns) []Hit {
				for _, a := range d.args {
					p, _, _ := strings.Cut(a, "/")
					lo, hi, rng := strings.Cut(p, "-")
					if !rng {
						hi = lo
					}
					l, e1 := strconv.Atoi(lo)
					h, e2 := strconv.Atoi(hi)
					if e1 == nil && e2 == nil && l <= 22 && 22 <= h {
						return []Hit{*dkHit(d, "Running SSH in a container adds a remote login service to attack.")}
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-EXPOSE-002", Title: "EXPOSE lists a port outside 0-65535", Severity: Low, Category: CatValidate, Types: stageT,
		Remediation: "Use a port number between 0 and 65535.",
		Check: func(r *Resource) []Hit {
			return dkEach(r, "EXPOSE", func(d dkIns) []Hit {
				for _, a := range d.args {
					p, _, _ := strings.Cut(a, "/")
					for _, part := range strings.Split(p, "-") {
						if n, err := strconv.Atoi(part); err == nil && n > 65535 {
							return []Hit{*dkHit(d, "Port "+part+" does not exist; the build or run fails.")}
						}
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-ADD-001", Title: "ADD used to copy local files", Severity: Low, Category: CatSecurity, CWE: "CWE-829", Types: stageT,
		Remediation: "Use COPY for local files; keep ADD only to unpack a local archive.",
		Check: func(r *Resource) []Hit {
			return dkEach(r, "ADD", func(d dkIns) []Hit {
				if len(d.args) < 2 {
					return nil
				}
				for _, s := range d.args[:len(d.args)-1] {
					if !strings.Contains(s, "://") && !strings.HasPrefix(s, "git@") && !dkArchive.MatchString(s) {
						h := dkHit(d, "ADD also fetches URLs and unpacks archives, so a changed source can do more than copy a file.")
						if dkAllLocal(d) {
							h.Fix = dkLineFix(r, d, "ADD ", "COPY ", "Use COPY for local files")
						}
						return []Hit{*h}
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-ADD-002", Title: "ADD downloads a remote file without a checksum", Severity: Medium, Category: CatSecurity, CWE: "CWE-494", Types: stageT,
		Remediation: "Add --checksum=sha256:<hash>, or download with curl and verify the hash in RUN.",
		Check: func(r *Resource) []Hit {
			return dkEach(r, "ADD", func(d dkIns) []Hit {
				if _, ok := d.flag("--checksum"); ok || len(d.args) < 2 {
					return nil
				}
				for _, s := range d.args[:len(d.args)-1] {
					if strings.Contains(s, "://") || strings.HasPrefix(s, "git@") {
						return []Hit{*dkHit(d, "Whatever the server returns for "+s+" goes into the image unverified.")}
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-COPY-001", Title: "COPY --from refers to its own stage", Severity: Medium, Category: CatValidate, Types: stageT, Blocking: true,
		Remediation: "Point --from at an earlier stage or an image.",
		Check: func(r *Resource) []Hit {
			name, _ := r.Attrs["name"].(string)
			return dkEach(r, "COPY", func(d dkIns) []Hit {
				if v, ok := d.flag("--from"); ok && name != "" && strings.EqualFold(v, name) {
					return []Hit{*dkHit(d, "A stage cannot copy from itself; the build fails with a circular dependency.")}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-COPY-002", Title: "COPY with several sources has a destination without a trailing slash", Severity: Medium, Category: CatValidate, Types: stageT, Blocking: true,
		Remediation: "End the destination with / when copying more than one source.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, cmd := range []string{"COPY", "ADD"} {
				out = append(out, dkEach(r, cmd, func(d dkIns) []Hit {
					if len(d.args) > 2 && !strings.Contains(d.value, "<<") && !strings.HasSuffix(d.args[len(d.args)-1], "/") {
						return []Hit{*dkHit(d, "Docker rejects several sources unless the destination is a directory ending in /.")}
					}
					return nil
				})...)
			}
			return out
		}},
	{ID: "TG-DOCKER-COPY-003", Title: "COPY --chown gives the app user ownership of its files", Severity: Info, Category: CatBestPrac, CWE: "CWE-732", Types: stageT,
		Remediation: "Leave program files owned by root and grant the app user write access only where it needs it.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, cmd := range []string{"COPY", "ADD"} {
				out = append(out, dkEach(r, cmd, func(d dkIns) []Hit {
					if _, ok := d.flag("--chown"); ok {
						return []Hit{*dkHit(d, "A compromised process can rewrite the files it runs from.")}
					}
					return nil
				})...)
			}
			return out
		}},
	{ID: "TG-DOCKER-COPY-004", Title: "Private key or credential file copied into the image", Severity: High, Category: CatSecurity, CWE: "CWE-538", Types: stageT,
		Remediation: "Keep credentials out of the image: use RUN --mount=type=secret at build time and runtime secrets at run time.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, cmd := range []string{"COPY", "ADD"} {
				out = append(out, dkEach(r, cmd, func(d dkIns) []Hit {
					if len(d.args) < 2 {
						return nil
					}
					dest := strings.ToLower(d.args[len(d.args)-1])
					for _, s := range d.args[:len(d.args)-1] {
						if dkSecretRE.MatchString(strings.TrimRight(s, "/")) && !dkPublicCert(s, dest) {
							return []Hit{*dkHit(d, s+" ends up in an image layer that anyone who pulls the image can read.")}
						}
					}
					return nil
				})...)
			}
			return out
		}},
	{ID: "TG-DOCKER-RUN-001", Title: "RUN uses apt instead of apt-get", Severity: Low, Category: CatReliability, Types: stageT,
		Remediation: "Use apt-get (or apt-cache) in scripts; apt's interface is not stable.",
		Check: func(r *Resource) []Hit {
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if w = dkStrip(w); len(w) > 1 && w[0] == "apt" {
					return dkHit(d, "apt warns that its command line can change between releases, which can break the build.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-002", Title: "Package index updated in a RUN that installs nothing", Severity: Low, Category: CatReliability, Types: stageT,
		Remediation: "Run the update and the install in the same RUN (apt-get update && apt-get install ...).",
		Check: func(r *Resource) []Hit {
			return dkRun(r, func(d dkIns, text string) []Hit {
				update, install := false, false
				for _, w := range dkCommands(text) {
					w = dkStrip(w)
					if len(w) < 2 {
						continue
					}
					if w[0] == "apt-get" || w[0] == "apt" || w[0] == "apk" {
						for _, x := range w[1:] {
							if dkUpdateRE.MatchString(x) {
								update = true
							}
							if contains([]string{x}, "install", "add", "upgrade", "dist-upgrade", "reinstall", "source-install") {
								install = true
							}
						}
					}
				}
				if update && !install {
					return []Hit{*dkHit(d, "The cached layer keeps an old package index, so later installs fetch stale or missing versions.")}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-003", Title: "RUN uses sudo", Severity: Medium, Category: CatSecurity, CWE: "CWE-250", Types: stageT,
		Remediation: "Run privileged steps before switching USER, and drop sudo from the image.",
		Check: func(r *Resource) []Hit {
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				for _, x := range w {
					if x == "sudo" {
						return dkHit(d, "sudo in an image means the runtime user can become root.")
					}
					if !strings.Contains(x, "=") {
						break
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-004", Title: "RUN pipes a downloaded script into a shell", Severity: Medium, Category: CatSecurity, CWE: "CWE-494", Types: stageT,
		Remediation: "Download the script, verify its checksum or signature, then run it.",
		Check: func(r *Resource) []Hit {
			return dkRun(r, func(d dkIns, text string) []Hit {
				if pipeShellRE.MatchString(text) {
					return []Hit{*dkHit(d, "Whatever the server returns runs as the build user, unreviewed.")}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-005", Title: "RUN sets a password with chpasswd", Severity: Medium, Category: CatSecurity, CWE: "CWE-259", Types: stageT,
		Remediation: "Do not bake passwords into images; use key-based access or set credentials at run time.",
		Check: func(r *Resource) []Hit {
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if w = dkStrip(w); len(w) > 0 && path.Base(w[0]) == "chpasswd" {
					return dkHit(d, "The password is in the Dockerfile and the image history.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-006", Title: "RUN changes directory with cd", Severity: Low, Category: CatBestPrac, Types: stageT,
		Remediation: "Use WORKDIR /absolute/path instead of cd to a relative path.",
		Check: func(r *Resource) []Hit {
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if len(w) == 2 && w[0] == "cd" && !dkAbsRE.MatchString(w[1]) && !strings.HasPrefix(w[1], "~") && w[1] != "-" {
					return dkHit(d, "Relative cd makes later instructions depend on where earlier ones left off.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-007", Title: "Stage uses both curl and wget", Severity: Info, Category: CatBestPrac, Types: stageT,
		Remediation: "Pick one download tool for the stage.",
		Check: func(r *Resource) []Hit {
			seen := map[string]bool{}
			var out []Hit
			dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if w = dkStrip(w); len(w) > 0 && (w[0] == "curl" || w[0] == "wget") {
					seen[w[0]] = true
					if seen["curl"] && seen["wget"] && len(out) == 0 {
						out = append(out, *dkHit(d, "Two tools doing the same job add size and attack surface."))
					}
				}
				return nil
			})
			return out
		}},
	{ID: "TG-DOCKER-RUN-008", Title: "RUN calls an interactive or system utility", Severity: Info, Category: CatBestPrac, Types: stageT,
		Remediation: "Remove commands like ps, top, kill, mount, service, vim or nano from the build.",
		Check: func(r *Resource) []Hit {
			bad := []string{"ps", "shutdown", "service", "free", "top", "kill", "mount", "ifconfig", "nano", "vim", "vi"}
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if w = dkStrip(w); len(w) > 0 && contains(bad, w[0]) {
					return dkHit(d, w[0]+" has no useful effect during an image build.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-009", Title: "RUN replaces the default shell", Severity: Low, Category: CatBestPrac, Types: stageT,
		Remediation: "Use the SHELL instruction to change the shell.",
		Check: func(r *Resource) []Hit {
			shells := []string{"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ash", "/bin/ksh", "/usr/bin/zsh", "/usr/bin/bash", "/etc/shells"}
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if w = dkStrip(w); len(w) > 1 && contains([]string{"mv", "chsh", "usermod", "ln"}, w[0]) && contains(w[1:], shells...) {
					return dkHit(d, "Swapping the shell by hand surprises later instructions and the base image.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-010", Title: "RUN pipes commands without pipefail", Severity: Low, Category: CatReliability, CWE: "CWE-754", Types: stageT,
		Remediation: `Add SHELL ["/bin/bash", "-o", "pipefail", "-c"] before the RUN, or set -o pipefail in it.`,
		Check: func(r *Resource) []Hit {
			pipefail := false
			var out []Hit
			for _, d := range dkInstrs(r.Attrs) {
				if d.cmd == "SHELL" && strings.Contains(d.value, "pipefail") {
					pipefail = true
				}
				if d.cmd == "RUN" && !d.json && !pipefail && !strings.Contains(d.value, "pipefail") && dkHasPipe(d.value) {
					out = append(out, *dkHit(d, "A failing command before the pipe is ignored, so a broken download can still produce an image."))
				}
			}
			return out
		}},
	{ID: "TG-DOCKER-RUN-011", Title: "RUN makes files world-writable", Severity: Low, Category: CatSecurity, CWE: "CWE-732", Types: stageT,
		Remediation: "Grant the narrowest mode that works (for example 755 or 644) and change ownership instead.",
		Check: func(r *Resource) []Hit {
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if w = dkStrip(w); len(w) > 1 && w[0] == "chmod" && contains(w[1:], "777", "0777", "a+rwx", "ugo+rwx", "o+w", "a+w") {
					return dkHit(d, "Any process in the container can replace these files.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-RUN-012", Title: "Consecutive RUN instructions", Severity: Info, Category: CatBestPrac, Types: stageT,
		Remediation: "Join consecutive RUN instructions with && to save layers.",
		Check: func(r *Resource) []Hit {
			prev := ""
			for _, d := range dkInstrs(r.Attrs) {
				if d.cmd == "RUN" && prev == "RUN" {
					return []Hit{*dkHit(d, "Each RUN adds a layer, so the image is larger and slower to pull.")}
				}
				prev = d.cmd
			}
			return nil
		}},
	{ID: "TG-DOCKER-TLS-001", Title: "Certificate validation is disabled during the build", Severity: High, Category: CatSecurity, CWE: "CWE-295", Types: bothT,
		Remediation: "Remove the option or variable that disables TLS verification; add the needed CA certificate instead.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, d := range dkInstrs(r.Attrs) {
				switch d.cmd {
				case "RUN":
					if tlsOffText(d.shell()) {
						out = append(out, *dkHit(d, "Downloads in this step accept any certificate, so a network attacker can swap what is installed."))
					}
				case "ENV", "ARG":
					for _, kv := range dockerPairs(d.cmd, d.value) {
						if tlsOffEnv(kv[0], kv[1]) {
							out = append(out, *dkHit(d, kv[0]+" turns off certificate checks for every later download."))
						}
					}
				}
			}
			return out
		}},
	{ID: "TG-DOCKER-PKG-001", Title: "Package signature checks are disabled", Severity: High, Category: CatSecurity, CWE: "CWE-494", Types: stageT,
		Remediation: "Remove --allow-untrusted, --allow-unauthenticated, --force-yes, --nogpgcheck, --nosignature and trusted=yes; import the repository key instead.",
		Check: func(r *Resource) []Hit {
			return dkRun(r, func(d dkIns, text string) []Hit {
				for _, re := range unsignedREs {
					if re.MatchString(text) {
						return []Hit{*dkHit(d, "Packages are installed without verifying who built them, so a tampered package goes in unnoticed.")}
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-PKG-002", Title: "Package install waits for confirmation", Severity: Medium, Category: CatReliability, Types: stageT,
		Remediation: "Pass -y (apt-get, yum, dnf) or -n (zypper) so the install runs unattended.",
		Check: func(r *Resource) []Hit {
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				p, ok := dkInstall(w)
				if ok && len(p.pkgs) > 0 && contains([]string{"apt-get", "apt", "yum", "dnf", "tdnf", "zypper"}, p.mgr) && !dkAssumeYes(p) {
					return dkHit(d, p.mgr+" prompts for confirmation and the build has no terminal, so it aborts.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-PKG-003", Title: "Package installed without a pinned version", Severity: Low, Category: CatReliability, CWE: "CWE-1357", Types: stageT,
		Remediation: "Pin versions (apt-get install pkg=1.2.3, apk add pkg=1.2.3, pip install pkg==1.2.3, npm install pkg@1.2.3) or install from a lock file.",
		Check: func(r *Resource) []Hit {
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				p, ok := dkInstall(w)
				if !ok || p.mgr == "pip" && p.has("-r", "--requirement", "-e", "--editable", "-c", "--constraint") {
					return nil
				}
				for _, pkg := range p.pkgs {
					if !dkPinned(p, pkg) {
						return dkHit(d, pkg+" installs whatever version is current, so rebuilds can change behaviour or break.")
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-PKG-004", Title: "Package manager cache left in the image", Severity: Info, Category: CatBestPrac, Types: stageT,
		Remediation: "Clean up in the same RUN (rm -rf /var/lib/apt/lists/*, apk add --no-cache, yum/dnf clean all, zypper clean, pip --no-cache-dir) or use RUN --mount=type=cache.",
		Check: func(r *Resource) []Hit {
			if shipped, _ := r.Attrs["shipped"].(bool); !shipped {
				return nil
			}
			env, _ := r.Attrs["env"].(map[string]any)
			return dkRun(r, func(d dkIns, text string) []Hit {
				if m, _ := d.flag("--mount"); strings.Contains(m, "type=cache") {
					return nil
				}
				for _, w := range dkCommands(text) {
					p, ok := dkInstall(w)
					if !ok || len(p.pkgs) == 0 {
						continue
					}
					left := false
					switch p.mgr {
					case "apt-get", "apt":
						left = !strings.Contains(text, "/var/lib/apt/lists")
					case "apk":
						left = !p.has("--no-cache") && !strings.Contains(text, "/var/cache/apk")
					case "yum":
						left = !strings.Contains(text, "yum clean all") && !strings.Contains(text, "/var/cache/yum")
					case "dnf", "tdnf":
						left = !strings.Contains(text, p.mgr+" clean all") && !strings.Contains(text, "/var/cache/"+p.mgr)
					case "zypper":
						left = !strings.Contains(text, "zypper clean") && !strings.Contains(text, "zypper cc")
					case "pip":
						left = !p.has("--no-cache-dir") && env["PIP_NO_CACHE_DIR"] == nil
					}
					if left {
						return []Hit{*dkHit(d, "The "+p.mgr+" cache stays in the layer and makes the image larger.")}
					}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-PKG-005", Title: "apt-get install pulls recommended packages", Severity: Info, Category: CatBestPrac, Types: stageT,
		Remediation: "Add --no-install-recommends to apt-get install.",
		Check: func(r *Resource) []Hit {
			if shipped, _ := r.Attrs["shipped"].(bool); !shipped {
				return nil
			}
			return dkCommandsRun(r, func(d dkIns, w []string) *Hit {
				if p, ok := dkInstall(w); ok && p.mgr == "apt-get" && len(p.pkgs) > 0 && !p.has("--no-install-recommends") {
					return dkHit(d, "Recommended packages add size and attack surface the image does not need.")
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-SECRET-001", Title: "Secret passed as a build argument", Severity: Medium, Category: CatSecurity, CWE: "CWE-214", Types: stageT,
		Remediation: "Pass secrets with RUN --mount=type=secret at build time and inject them at run time; never as ARG.",
		Check: func(r *Resource) []Hit {
			if shipped, _ := r.Attrs["shipped"].(bool); !shipped {
				return nil
			}
			var out []Hit
			for _, d := range dkInstrs(r.Attrs) {
				if d.cmd != "ARG" {
					continue
				}
				for _, kv := range dockerPairs(d.cmd, d.value) {
					if secretAttrRE.MatchString(kv[0]) {
						out = append(out, *dkHit(d, "Build argument "+kv[0]+" is recorded in the image history, where anyone who pulls the image can read it."))
					}
				}
			}
			return out
		}},
	{ID: "TG-DOCKER-MAINT-001", Title: "MAINTAINER is deprecated", Severity: Low, Category: CatBestPrac, Types: stageT,
		Remediation: `Use LABEL org.opencontainers.image.authors="..." instead.`,
		Check: func(r *Resource) []Hit {
			return dkEach(r, "MAINTAINER", func(d dkIns) []Hit {
				h := dkHit(d, "MAINTAINER is deprecated and tools read the authors label instead.")
				if v := strings.TrimSpace(d.value); v != "" && !strings.Contains(v, "\n") {
					h.Fix = dkLineFix(r, d, "MAINTAINER "+v, "LABEL org.opencontainers.image.authors="+strconv.Quote(v), "Use the OCI authors label")
				}
				return []Hit{*h}
			})
		}},
	{ID: "TG-DOCKER-WORKDIR-001", Title: "WORKDIR is a relative path", Severity: Low, Category: CatReliability, Types: stageT,
		Remediation: "Use an absolute path in WORKDIR.",
		Check: func(r *Resource) []Hit {
			return dkEach(r, "WORKDIR", func(d dkIns) []Hit {
				if !dkAbsRE.MatchString(strings.TrimSpace(d.value)) {
					return []Hit{*dkHit(d, "The directory depends on earlier WORKDIRs, so reordering instructions moves it.")}
				}
				return nil
			})
		}},
	{ID: "TG-DOCKER-CMD-001", Title: "Stage has more than one CMD", Severity: Low, Category: CatReliability, Types: stageT,
		Remediation: "Keep one CMD per stage.",
		Check: func(r *Resource) []Hit {
			return dkSecond(r, "CMD", "Only the last CMD takes effect; the others are dead code.")
		}},
	{ID: "TG-DOCKER-CMD-002", Title: "Stage has more than one ENTRYPOINT", Severity: Low, Category: CatReliability, Types: stageT,
		Remediation: "Keep one ENTRYPOINT per stage.",
		Check: func(r *Resource) []Hit {
			return dkSecond(r, "ENTRYPOINT", "Only the last ENTRYPOINT takes effect; the others are dead code.")
		}},
	{ID: "TG-DOCKER-CMD-003", Title: "CMD or ENTRYPOINT uses shell form", Severity: Low, Category: CatReliability, Types: stageT,
		Remediation: `Use exec form, for example CMD ["app", "--flag"].`,
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, d := range dkInstrs(r.Attrs) {
				if (d.cmd == "CMD" || d.cmd == "ENTRYPOINT") && !d.json && strings.TrimSpace(d.value) != "" {
					out = append(out, *dkHit(d, "The process runs under /bin/sh -c and does not receive SIGTERM, so shutdowns are not graceful."))
				}
			}
			return out
		}},
}

func dkSecond(r *Resource, cmd, msg string) []Hit {
	n := 0
	for _, d := range dkInstrs(r.Attrs) {
		if d.cmd == cmd {
			if n++; n == 2 {
				return []Hit{*dkHit(d, msg)}
			}
		}
	}
	return nil
}

var dkPipeRE = regexp.MustCompile(`[^|]\|[^|]`)

// dkHasPipe reports a single | outside quotes.
func dkHasPipe(s string) bool {
	var b strings.Builder
	var q rune
	for _, c := range s {
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
			continue
		case c == '"' || c == '\'':
			q = c
			continue
		}
		b.WriteRune(c)
	}
	return dkPipeRE.MatchString(" " + b.String() + " ")
}

// Rules for docker-compose files (resource shapes in format_compose.go).

type csItem struct {
	path string
	val  any
}

func csList(r *Resource, key string) []csItem {
	var out []csItem
	for i, v := range asList(r.Attrs[key]) {
		out = append(out, csItem{key + "." + strconv.Itoa(i), v})
	}
	return out
}

func csStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

// csMount reads a short or long volume entry.
func csMount(v any) (src, typ, propagation string) {
	switch t := v.(type) {
	case string:
		src, _, _ = strings.Cut(t, ":")
		typ = "volume"
		if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") {
			typ = "bind"
		}
		if parts := strings.Split(t, ":"); len(parts) == 3 {
			for _, o := range strings.Split(parts[2], ",") {
				if strings.Contains(o, "shared") || strings.Contains(o, "slave") {
					propagation = o
				}
			}
		}
	case map[string]any:
		src, _ = t["source"].(string)
		typ, _ = t["type"].(string)
		propagation, _ = get(t, "bind.propagation").(string)
	}
	return
}

func csSensitive(p string) bool {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return true // the root directory
	}
	for _, d := range []string{"/bin", "/sbin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/proc", "/root", "/run", "/srv", "/usr", "/var", "/sys"} {
		if p == d {
			return true
		}
	}
	// Below these, anything is system state; /var, /srv, /home and /run also hold ordinary data.
	for _, d := range []string{"/boot", "/dev", "/etc", "/proc", "/root", "/sys", "/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

func csDockerSock(p string) bool { return strings.HasSuffix(p, "/docker.sock") }

// csEnv reads environment as a map or a list of KEY=VALUE.
func csEnv(v any, prefix string) []csItem {
	var out []csItem
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			out = append(out, csItem{prefix + "." + k, [2]any{k, x}})
		}
	case []any:
		for i, x := range t {
			if s, ok := x.(string); ok {
				k, val, _ := strings.Cut(s, "=")
				out = append(out, csItem{prefix + "." + strconv.Itoa(i), [2]any{k, val}})
			}
		}
	}
	return out
}

// csPort splits a published port into host IP, host port and container port.
func csPort(v any) (ip, host, ctr string) {
	if m, ok := v.(map[string]any); ok {
		ip, _ = m["host_ip"].(string)
		return ip, csStr(m["published"]), csStr(m["target"])
	}
	s := csStr(v)
	s, _, _ = strings.Cut(s, "/")
	if strings.HasPrefix(s, "[") { // [::1]:80:80
		end := strings.Index(s, "]")
		ip, s = s[1:max(end, 1)], strings.TrimPrefix(s[end+1:], ":")
	}
	parts := strings.Split(s, ":")
	switch {
	case len(parts) == 1:
		return ip, "", parts[0]
	case len(parts) == 2:
		return ip, parts[0], parts[1]
	case ip != "": // [::1]:8080:80 with the address already taken off
		return ip, parts[len(parts)-2], parts[len(parts)-1]
	default:
		return parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1]
	}
}

func csLimit(r *Resource, short []string, deploy string) bool {
	for _, k := range short {
		if r.Attrs[k] != nil {
			return true
		}
	}
	return r.get("deploy.resources.limits."+deploy) != nil
}

func csSecOpt(r *Resource, want ...string) (string, bool) {
	for _, it := range csList(r, "security_opt") {
		s := strings.ReplaceAll(csStr(it.val), "=", ":")
		for _, w := range want {
			if strings.HasPrefix(s, w) {
				return it.path, true
			}
		}
	}
	return "", false
}

func csHost(key, msg string) func(r *Resource) []Hit {
	return func(r *Resource) []Hit {
		if s, _ := r.Attrs[key].(string); s == "host" {
			return []Hit{{Path: key, Msg: msg}}
		}
		return nil
	}
}

var (
	svcT = []string{"compose_service"}
	cfT  = []string{"compose"}
)

var csDangerCaps = []string{"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF"}

var composeRules = []Rule{
	{ID: "TG-COMPOSE-001", Title: "Service runs privileged", Severity: High, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: "Remove privileged: true and add only the capabilities or devices the service needs.",
		Check: func(r *Resource) []Hit {
			if is(r.Attrs["privileged"], true) {
				return []Hit{{Path: "privileged", Msg: "The container has every kernel capability and all host devices, so escaping to the host is trivial."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-002", Title: "Docker socket mounted into a service", Severity: High, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: "Do not mount docker.sock; use a socket proxy limited to the API calls the service needs.",
		Check: func(r *Resource) []Hit {
			for _, it := range csList(r, "volumes") {
				if src, _, _ := csMount(it.val); csDockerSock(src) {
					return []Hit{{Path: it.path, Msg: "Anyone controlling this container can start privileged containers and take over the host."}}
				}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-003", Title: "Service shares the host network", Severity: Medium, Category: CatSecurity, CWE: "CWE-653", Types: svcT,
		Remediation: "Remove network_mode: host and publish only the ports the service needs.",
		Check:       csHost("network_mode", "The container sees every host interface and can bind any host port.")},
	{ID: "TG-COMPOSE-004", Title: "Service shares the host process namespace", Severity: Medium, Category: CatSecurity, CWE: "CWE-653", Types: svcT,
		Remediation: "Remove pid: host.",
		Check:       csHost("pid", "The container can see and signal every process on the host.")},
	{ID: "TG-COMPOSE-005", Title: "Service shares the host IPC namespace", Severity: Medium, Category: CatSecurity, CWE: "CWE-653", Types: svcT,
		Remediation: "Remove ipc: host.",
		Check:       csHost("ipc", "The container can read shared memory of host processes.")},
	{ID: "TG-COMPOSE-006", Title: "Service shares the host user namespace", Severity: Medium, Category: CatSecurity, CWE: "CWE-653", Types: svcT,
		Remediation: "Remove userns_mode: host.",
		Check:       csHost("userns_mode", "Root in the container is root on the host when user namespace remapping is on.")},
	{ID: "TG-COMPOSE-007", Title: "Sensitive host directory mounted", Severity: High, Category: CatSecurity, CWE: "CWE-668", Types: []string{"compose_service", "compose"},
		Remediation: "Mount only an application directory, read-only where possible, never /, /etc, /proc, /var or similar.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			if r.Type == "compose" {
				vols, _ := r.Attrs["volumes"].(map[string]any)
				for name, v := range vols {
					for _, k := range []string{"device", "mountpoint"} {
						if p, ok := get(v, "driver_opts."+k).(string); ok && strings.HasPrefix(p, "/") && csSensitive(p) {
							out = append(out, Hit{Path: "volumes." + name + ".driver_opts." + k, Msg: "Volume " + name + " exposes host path " + p + " to every service that uses it."})
						}
					}
				}
				return out
			}
			for _, it := range csList(r, "volumes") {
				src, typ, _ := csMount(it.val)
				if typ == "bind" && strings.HasPrefix(src, "/") && csSensitive(src) && !csDockerSock(src) {
					out = append(out, Hit{Path: it.path, Msg: "The service can read or change host files under " + src + "."})
				}
			}
			return out
		}},
	{ID: "TG-COMPOSE-008", Title: "Service adds Linux capabilities", Severity: Medium, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: "Remove cap_add entries the service does not strictly need; never add ALL or SYS_ADMIN.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, it := range csList(r, "cap_add") {
				c := strings.TrimPrefix(strings.ToUpper(csStr(it.val)), "CAP_")
				h := Hit{Path: it.path, Msg: c + " widens what a compromised process can do to the host."}
				if contains(csDangerCaps, c) {
					h.Sev, h.Msg = High, c+" is close to full root on the host."
				}
				out = append(out, h)
			}
			return out
		}},
	{ID: "TG-COMPOSE-009", Title: "Service keeps the default capabilities", Severity: Low, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: "Add cap_drop: [ALL] and add back only what the service needs.",
		Check: func(r *Resource) []Hit {
			if r.Attrs["cap_drop"] == nil {
				return []Hit{{Path: "", Msg: "Defaults such as NET_RAW and CHOWN stay available to an attacker."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-010", Title: "Seccomp or AppArmor confinement disabled", Severity: Medium, Category: CatSecurity, CWE: "CWE-693", Types: svcT,
		Remediation: "Remove seccomp:unconfined and apparmor:unconfined from security_opt.",
		Check: func(r *Resource) []Hit {
			if p, ok := csSecOpt(r, "seccomp:unconfined", "apparmor:unconfined"); ok {
				return []Hit{{Path: p, Msg: "Every system call is allowed, so kernel exploits are easier."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-011", Title: "Privilege escalation not blocked", Severity: Low, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: `Add security_opt: ["no-new-privileges:true"].`,
		Check: func(r *Resource) []Hit {
			if p, ok := csSecOpt(r, "no-new-privileges"); !ok || strings.Contains(csStr(r.get(p)), "false") {
				return []Hit{{Path: "security_opt", Msg: "setuid binaries in the image can still raise a process to root."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-012", Title: "Service has no memory limit", Severity: Low, Category: CatReliability, CWE: "CWE-770", Types: svcT,
		Remediation: "Set deploy.resources.limits.memory (or mem_limit).",
		Check: func(r *Resource) []Hit {
			if !csLimit(r, []string{"mem_limit"}, "memory") {
				return []Hit{{Path: "", Msg: "One service can use all host memory and get other services killed."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-013", Title: "Service has no CPU limit", Severity: Low, Category: CatReliability, CWE: "CWE-770", Types: svcT,
		Remediation: "Set deploy.resources.limits.cpus (or cpus).",
		Check: func(r *Resource) []Hit {
			if !csLimit(r, []string{"cpus", "cpu_quota"}, "cpus") {
				return []Hit{{Path: "", Msg: "One service can starve every other service of CPU."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-014", Title: "Service has no process limit", Severity: Low, Category: CatReliability, CWE: "CWE-770", Types: svcT,
		Remediation: "Set pids_limit (or deploy.resources.limits.pids) to a positive number.",
		Check: func(r *Resource) []Hit {
			v := r.Attrs["pids_limit"]
			if v == nil {
				v = r.get("deploy.resources.limits.pids")
			}
			if n, ok := asFloat(v); v == nil || ok && n <= 0 {
				return []Hit{{Path: "pids_limit", Msg: "A fork bomb in the container can exhaust host process slots."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-015", Title: "Service has no health check", Severity: Low, Category: CatReliability, CWE: "CWE-754", Types: svcT,
		Remediation: "Add a healthcheck with a test command (or rely on the image's HEALTHCHECK and do not disable it).",
		Check: func(r *Resource) []Hit {
			hc, ok := r.Attrs["healthcheck"].(map[string]any)
			if !ok {
				return []Hit{{Path: "", Msg: "Compose cannot tell a hung service from a healthy one."}}
			}
			if is(hc["disable"], true) || contains(asStrings(hc["test"]), "NONE") {
				return []Hit{{Path: "healthcheck", Msg: "The health check is turned off."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-016", Title: "Port published on every host interface", Severity: Low, Category: CatSecurity, CWE: "CWE-668", Types: svcT,
		Remediation: `Bind published ports to an address, for example "127.0.0.1:8080:80".`,
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, it := range csList(r, "ports") {
				if ip, _, _ := csPort(it.val); ip == "" || ip == "0.0.0.0" || ip == "::" {
					out = append(out, Hit{Path: it.path, Msg: "The port is reachable from every network the host is on."})
				}
			}
			return out
		}},
	{ID: "TG-COMPOSE-017", Title: "Privileged host port published", Severity: Low, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: "Publish on a port above 1023, or drop NET_BIND_SERVICE and put a proxy in front.",
		Check: func(r *Resource) []Hit {
			if contains(asStrings(r.Attrs["cap_drop"]), "NET_BIND_SERVICE", "ALL") {
				return nil
			}
			var out []Hit
			for _, it := range csList(r, "ports") {
				_, host, _ := csPort(it.val)
				lo, _, _ := strings.Cut(host, "-")
				if n, err := strconv.Atoi(lo); err == nil && n > 0 && n < 1024 {
					out = append(out, Hit{Path: it.path, Msg: "Ports below 1024 are reserved for system services."})
				}
			}
			return out
		}},
	{ID: "TG-COMPOSE-018", Title: "Service uses a custom cgroup parent", Severity: Low, Category: CatSecurity, CWE: "CWE-770", Types: svcT,
		Remediation: "Remove cgroup_parent unless the host cgroup is set up for it.",
		Check: func(r *Resource) []Hit {
			if r.Attrs["cgroup_parent"] != nil {
				return []Hit{{Path: "cgroup_parent", Msg: "The container's resource limits now depend on a host cgroup outside Docker's control."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-019", Title: "on-failure restart is not capped at 5 attempts", Severity: Info, Category: CatReliability, Types: svcT,
		Remediation: `Use restart: "on-failure:5" (or deploy.restart_policy.max_attempts: 5).`,
		Check: func(r *Resource) []Hit {
			if s, _ := r.Attrs["restart"].(string); strings.HasPrefix(s, "on-failure:") && s != "on-failure:5" {
				return []Hit{{Path: "restart", Msg: "A crashing service restarts more often than it should, hiding the failure."}}
			}
			if c, _ := r.get("deploy.restart_policy.condition").(string); c == "on-failure" {
				if n, ok := asFloat(r.get("deploy.restart_policy.max_attempts")); !ok || n != 5 {
					return []Hit{{Path: "deploy.restart_policy", Msg: "A crashing service restarts more often than it should, hiding the failure."}}
				}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-020", Title: "Bind mount propagates mounts to or from the host", Severity: Medium, Category: CatSecurity, CWE: "CWE-668", Types: svcT,
		Remediation: "Use the default private propagation; remove shared, rshared, slave and rslave.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, it := range csList(r, "volumes") {
				if _, _, p := csMount(it.val); p != "" && p != "private" && p != "rprivate" {
					out = append(out, Hit{Path: it.path, Msg: "Mounts made inside the container appear on the host (or the reverse)."})
				}
			}
			return out
		}},
	{ID: "TG-COMPOSE-021", Title: "Named volume shared by several services", Severity: Info, Category: CatSecurity, CWE: "CWE-668", Types: cfT,
		Remediation: "Give each service its own volume, or mount the shared one read-only where it is only read.",
		Check: func(r *Resource) []Hit {
			services, _ := r.Attrs["services"].(map[string]any)
			users := map[string][]string{}
			for name, sv := range services {
				m, _ := sv.(map[string]any)
				for _, v := range asList(m["volumes"]) {
					if src, typ, _ := csMount(v); typ == "volume" && src != "" {
						users[src] = append(users[src], name)
					}
				}
			}
			var out []Hit
			vols, _ := r.Attrs["volumes"].(map[string]any)
			for v := range vols {
				if len(users[v]) > 1 {
					out = append(out, Hit{Path: "volumes." + v, Msg: "A compromised service can plant files that another service reads."})
				}
			}
			return out
		}},
	{ID: "TG-COMPOSE-022", Title: "Service image uses the latest tag or no tag", Severity: Low, Category: CatSecurity, CWE: "CWE-1357", Types: svcT,
		Remediation: "Pin the image to a version tag, ideally with a digest.",
		Check: func(r *Resource) []Hit {
			img, _ := r.Attrs["image"].(string)
			if img != "" && r.Attrs["build"] == nil && imageRef(img) == "latest" {
				return []Hit{{Path: "image", Msg: "Every pull can bring a different " + img + "."}}
			}
			return nil
		}},
	{ID: "TG-COMPOSE-023", Title: "Secret written in the service environment list", Severity: High, Category: CatSecurity, CWE: "CWE-798", Types: svcT,
		Remediation: "Read the value from an .env file kept out of git, ${VAR} substitution, or compose secrets.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			env, _ := r.Attrs["environment"].([]any) // the mapping form is covered by TG-SEC-001
			for _, it := range csEnv(env, "environment") {
				kv := it.val.([2]any)
				if k, _ := kv[0].(string); literalSecret(k, kv[1]) {
					out = append(out, Hit{Path: it.path, Msg: k + " is committed with the compose file."})
				}
			}
			return out
		}},
	{ID: "TG-COMPOSE-024", Title: "Host device mapped into a service", Severity: Medium, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: "Remove devices entries the service does not need.",
		Check: func(r *Resource) []Hit {
			var out []Hit
			for _, it := range csList(r, "devices") {
				out = append(out, Hit{Path: it.path, Msg: "Direct device access can bypass container isolation."})
			}
			return out
		}},
	{ID: "TG-COMPOSE-025", Title: "Service runs as root", Severity: Low, Category: CatSecurity, CWE: "CWE-250", Types: svcT,
		Remediation: "Set user to an unprivileged UID, or remove user: root.",
		Check: func(r *Resource) []Hit {
			if dkRoot(csStr(r.Attrs["user"])) {
				return []Hit{{Path: "user", Msg: "The service process runs as root."}}
			}
			return nil
		}},
}

// dkPublicCert is true for certificates that are meant to be public, such as a
// CA bundle installed into the trust store.
func dkPublicCert(src, dest string) bool {
	name := strings.ToLower(src[strings.LastIndex(src, "/")+1:])
	return strings.Contains(dest, "ca-certificates") || strings.Contains(dest, "/certs") ||
		strings.HasSuffix(name, ".pem") && (strings.Contains(name, "ca") || strings.Contains(name, "cert") || strings.Contains(name, "pub") || strings.Contains(name, "chain"))
}

// dkLineFix edits the instruction's first line; the fixer checks the line still reads old.
func dkLineFix(r *Resource, d dkIns, old, new, desc string) *Fix {
	line := r.line(d.path())
	if line == 0 {
		return nil
	}
	return &Fix{Format: FormatDockerfile, Line: line, Old: old, New: new, Description: desc}
}

// dkAllLocal is true when every ADD source is a local, non-archive path, so COPY does the same.
func dkAllLocal(d dkIns) bool {
	for _, s := range d.args[:len(d.args)-1] {
		if strings.Contains(s, "://") || strings.HasPrefix(s, "git@") || dkArchive.MatchString(s) {
			return false
		}
	}
	return len(d.flags) == 0
}
