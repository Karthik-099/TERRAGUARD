package vuln

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func pkgSet(ps []Package) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Ecosystem+":"+p.Name+"@"+p.Version)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func TestLockfiles(t *testing.T) {
	cases := map[string]struct{ content, want string }{
		"go.mod": {"module x\n\ngo 1.22\n\nrequire golang.org/x/net v0.17.0\nrequire (\n\tgithub.com/a/b v1.2.3+incompatible // indirect\n)\n",
			"Go:github.com/a/b@1.2.3 Go:golang.org/x/net@0.17.0"},
		"go.sum": {"golang.org/x/net v0.17.0 h1:abc=\ngolang.org/x/net v0.17.0/go.mod h1:def=\n", "Go:golang.org/x/net@0.17.0"},
		"package-lock.json": {`{"lockfileVersion": 3, "packages": {"": {"name": "app"},
  "node_modules/lodash": {"version": "4.17.15"},
  "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
  "node_modules/ws": {"link": true}}}`, "npm:@scope/b@1.0.0 npm:lodash@4.17.15"},
		"sub/package-lock.json": {`{"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.15", "dependencies": {"minimist": {"version": "0.0.8"}}}}}`,
			"npm:lodash@4.17.15 npm:minimist@0.0.8"},
		"yarn.lock": {"# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.0\"\n\nlodash@^4.17.0:\n  version \"4.17.15\"\n",
			"npm:@babel/core@7.1.0 npm:lodash@4.17.15"},
		"berry/yarn.lock": {"__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.15\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n", "npm:lodash@4.17.15"},
		"pnpm-lock.yaml": {"lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies: {}\n\npackages:\n\n  '@babel/core@7.1.0':\n    resolution: {integrity: x}\n\n  lodash@4.17.15:\n    resolution: {integrity: y}\n\nsnapshots:\n\n  lodash@4.17.15: {}\n",
			"npm:@babel/core@7.1.0 npm:lodash@4.17.15"},
		"v5/pnpm-lock.yaml": {"lockfileVersion: 5.4\npackages:\n  /lodash/4.17.15:\n    dev: false\n  /@scope/b/1.0.0_react@18.0.0:\n    dev: false\n", "npm:@scope/b@1.0.0 npm:lodash@4.17.15"},
		"requirements.txt":  {"# pins\nDjango==3.2.0\nrequests[socks] == 2.19.1 ; python_version > '3'\nflask>=2.0\n-r other.txt\n", "PyPI:Django@3.2.0 PyPI:requests@2.19.1"},
		"poetry.lock":       {"[[package]]\nname = \"jinja2\"\nversion = \"2.10\"\n\n[package.dependencies]\nversion = \"9\"\n", "PyPI:jinja2@2.10"},
		"Pipfile.lock":      {`{"default": {"urllib3": {"version": "==1.24.1"}}, "develop": {"pytest": {"version": "==7.0.0"}}}`, "PyPI:pytest@7.0.0 PyPI:urllib3@1.24.1"},
		"Cargo.lock":        {"version = 3\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"\n", "crates.io:time@0.1.43"},
		"Gemfile.lock": {"GIT\n  remote: x\n  specs:\n    mine (1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n",
			"RubyGems:nokogiri@1.13.0 RubyGems:rack@2.2.3"},
		"composer.lock":      {`{"packages": [{"name": "guzzlehttp/guzzle", "version": "v7.4.0"}], "packages-dev": [{"name": "x/y", "version": "dev-main"}]}`, "Packagist:guzzlehttp/guzzle@7.4.0"},
		"packages.lock.json": {`{"version": 1, "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"}, "App.Core": {"type": "Project"}}}}`, "NuGet:Newtonsoft.Json@12.0.1"},
		"gradle.lockfile":    {"# comment\norg.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\nempty=\n", "Maven:org.apache.logging.log4j:log4j-core@2.14.1"},
	}
	for name, c := range cases {
		ps, err := ParseLockfile(name, []byte(c.content))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if got := pkgSet(ps); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, c.want)
		}
		for _, p := range ps {
			if p.Line == 0 || p.File != name {
				t.Errorf("%s: %s has file %q line %d", name, p.Name, p.File, p.Line)
			}
		}
	}
}

// writeDB indexes synthetic OSV records the way update does, from a local zip.
func writeDB(t *testing.T, dir, eco string, records ...string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, r := range records {
		w, _ := zw.Create(string(rune('a'+i)) + ".json")
		w.Write([]byte(r))
	}
	zw.Close()
	zp := filepath.Join(t.TempDir(), "all.zip")
	os.WriteFile(zp, buf.Bytes(), 0o644)
	stats, err := IndexZip(zp, dir, eco)
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := readMeta(dir)
	meta.Ecosystems[eco] = stats
	b, _ := json.Marshal(meta)
	os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o644)
}

const lodashRecord = `{"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"], "summary": "Prototype Pollution in lodash",
  "database_specific": {"severity": "HIGH"},
  "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.7.0"}, {"fixed": "4.17.19"}]}]}]}`

func TestIndexAndMatch(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "npm", lodashRecord, `{"id": "OLD", "withdrawn": "2021-01-01T00:00:00Z", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "versions": ["4.17.15"]}]}`)
	if _, err := IndexZip(filepath.Join(dir, "meta.json"), dir, "npm"); err == nil {
		t.Error("a non-zip file was accepted")
	}
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := MatchAll(db, []Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15", File: "package-lock.json", Line: 3}, {Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].ID != "GHSA-p6mc-m468-83gw" || ms[0].Fixed != "4.17.19" || ms[0].Severity != "HIGH" {
		t.Fatalf("matches = %+v", ms)
	}
	f := ms[0].Finding()
	if f.RuleID != ms[0].ID || f.Line != 3 || !strings.Contains(f.Message, "CVE-2020-8203") {
		t.Errorf("finding = %+v", f)
	}
	if _, err := MatchAll(db, []Package{{Ecosystem: "PyPI", Name: "x", Version: "1"}}); !IsMissing(err) {
		t.Errorf("missing ecosystem: %v", err)
	}
	if _, err := Open(t.TempDir()); !IsMissing(err) {
		t.Errorf("missing database: %v", err)
	}
}

type tarFile struct {
	name, body string
	typ        byte
}

func makeTar(t *testing.T, files []tarFile, gz bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w = &buf
	var zw *gzip.Writer
	tw := tar.NewWriter(w)
	if gz {
		zw = gzip.NewWriter(w)
		tw = tar.NewWriter(zw)
	}
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: f.name, Typeflag: typ, Mode: 0o644, Size: int64(len(f.body))}
		if typ == tar.TypeDir || typ == tar.TypeSymlink {
			h.Size = 0
			h.Linkname = f.body
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(f.body))
		}
	}
	tw.Close()
	if zw != nil {
		zw.Close()
	}
	return buf.Bytes()
}

const dpkgStatus = `Package: libssl3
Status: install ok installed
Source: openssl (3.0.11-1~deb12u1)
Version: 3.0.11-1~deb12u1+b1
Description: TLS
 long text: with colons

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: zlib1g
Status: install ok installed
Source: zlib
Version: 1:1.2.13.dfsg-1
`

func TestScanImage(t *testing.T) {
	base := makeTar(t, []tarFile{
		{name: "etc/", typ: tar.TypeDir},
		{name: "etc/os-release", body: "ID=debian\nVERSION_ID=\"12\"\n"},
		{name: "var/lib/dpkg/status", body: dpkgStatus},
		{name: "app/package-lock.json", body: `{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.15"}}}`},
		{name: "old/Cargo.lock", body: "[[package]]\nname = \"time\"\nversion = \"0.1.43\"\n"},
	}, false)
	top := makeTar(t, []tarFile{
		{name: "etc/", typ: tar.TypeDir},
		{name: "app/.wh.package-lock.json"},
		{name: "old/.wh..wh..opq"},
		{name: "srv/node_modules/x/package-lock.json", body: `{}`},
	}, true)
	manifest := `[{"Config": "c.json", "Layers": ["l1/layer.tar", "l2/layer.tar"]}]`
	archive := makeTar(t, []tarFile{{name: "manifest.json", body: manifest}, {name: "l1/layer.tar", body: string(base)}, {name: "l2/layer.tar", body: string(top)}}, false)
	img, err := ScanImage(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if img.OS != "Debian:12" {
		t.Errorf("os = %q", img.OS)
	}
	if got, want := pkgSet(img.Packages), "Debian:12:openssl@3.0.11-1~deb12u1 Debian:12:zlib@1:1.2.13.dfsg-1"; got != want {
		t.Errorf("packages:\n got %s\nwant %s", got, want)
	}

	// The same layers as an OCI layout.
	oci := makeTar(t, []tarFile{
		{name: "oci-layout", body: `{"imageLayoutVersion": "1.0.0"}`},
		{name: "index.json", body: `{"manifests": [{"digest": "sha256:att", "platform": {"os": "unknown"}}, {"digest": "sha256:m"}]}`},
		{name: "blobs/sha256/m", body: `{"layers": [{"digest": "sha256:l1"}]}`},
		{name: "blobs/sha256/l1", body: string(base)},
	}, false)
	img, err = ScanImage(bytes.NewReader(oci), int64(len(oci)))
	if err != nil {
		t.Fatal(err)
	}
	if got := pkgSet(img.Packages); !strings.Contains(got, "npm:lodash@4.17.15") || !strings.Contains(got, "crates.io:time@0.1.43") {
		t.Errorf("oci packages: %s", got)
	}

	notImage := makeTar(t, []tarFile{{name: "readme.txt", body: "hi"}}, false)
	if _, err := ScanImage(bytes.NewReader(notImage), int64(len(notImage))); err == nil || !strings.Contains(err.Error(), "docker save") {
		t.Errorf("non-image archive: %v", err)
	}
}

func TestOSEcosystem(t *testing.T) {
	for in, want := range map[string]string{
		"ID=alpine\nVERSION_ID=3.19.1\n":      "Alpine:v3.19",
		"ID=ubuntu\nVERSION_ID=\"22.04\"\n":   "Ubuntu:22.04",
		"ID=debian\nVERSION_ID=\"11\"\n":      "Debian:11",
		"ID=fedora\nVERSION_ID=39\n":          "",
		"ID=debian\nPRETTY_NAME=\"trixie\"\n": "",
	} {
		if got := osEcosystem([]byte(in)); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
	apk := "C:Q1abc\nP:libcrypto3\nV:3.1.4-r0\no:openssl\n\nP:musl\nV:1.2.4-r2\n"
	if got := pkgSet(parseApkInstalled([]byte(apk), "Alpine:v3.19", "lib/apk/db/installed")); got != "Alpine:v3.19:musl@1.2.4-r2 Alpine:v3.19:openssl@3.1.4-r0" {
		t.Errorf("apk = %s", got)
	}
}

func TestUbuntuSuffixLookup(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "Ubuntu", `{"id": "UBUNTU-CVE-1", "severity": [{"type": "Ubuntu", "score": "medium"}],
	  "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.12"}]}]}]}`)
	db, _ := Open(dir)
	ms, err := MatchAll(db, []Package{{Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "3.0.2-0ubuntu1.10"}})
	if err != nil || len(ms) != 1 || ms[0].Severity != "MEDIUM" {
		t.Fatalf("ms = %+v, err = %v", ms, err)
	}
}
