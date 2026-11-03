package vuln

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const (
	maxImageFile  = 32 << 20  // one file kept from a layer
	maxImageTotal = 512 << 20 // all files kept from all layers
	maxImageFiles = 5000
	maxManifest   = 4 << 20
)

// Image is what an offline image scan found.
type Image struct {
	OS       string    `json:"os,omitempty"` // OSV ecosystem, e.g. "Debian:12"
	Packages []Package `json:"packages"`
	Notes    []string  `json:"notes,omitempty"`
}

type tarEntry struct{ off, size int64 }

// ScanImage reads a `docker save` or OCI layout archive without running anything.
func ScanImage(r io.ReaderAt, size int64) (*Image, error) {
	entries, err := indexTar(io.NewSectionReader(r, 0, size))
	if err != nil {
		return nil, fmt.Errorf("not an image archive: %w", err)
	}
	open := func(name string) (*io.SectionReader, error) {
		e, ok := entries[path.Clean(strings.TrimPrefix(name, "./"))]
		if !ok {
			return nil, fmt.Errorf("archive has no %s", name)
		}
		return io.NewSectionReader(r, e.off, e.size), nil
	}
	layers, err := layerPaths(open, entries)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, l := range layers {
		sr, err := open(l)
		if err != nil {
			return nil, err
		}
		if err := applyLayer(sr, files); err != nil {
			return nil, fmt.Errorf("layer %s: %w", l, err)
		}
	}
	return inventory(files), nil
}

// indexTar records where each regular file's data starts, so layers are read in place.
func indexTar(sr *io.SectionReader) (map[string]tarEntry, error) {
	out := map[string]tarEntry{}
	tr := tar.NewReader(sr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		off, _ := sr.Seek(0, io.SeekCurrent)
		out[path.Clean(strings.TrimPrefix(h.Name, "./"))] = tarEntry{off, h.Size}
	}
	if len(out) == 0 {
		return nil, errors.New("empty archive")
	}
	return out, nil
}

func readJSON(open func(string) (*io.SectionReader, error), name string, v any) error {
	sr, err := open(name)
	if err != nil {
		return err
	}
	if sr.Size() > maxManifest {
		return fmt.Errorf("%s is too large for a manifest", name)
	}
	return json.NewDecoder(sr).Decode(v)
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}

func blobPath(digest string) string { return "blobs/" + strings.Replace(digest, ":", "/", 1) }

// layerPaths prefers docker's manifest.json and falls back to an OCI index.
func layerPaths(open func(string) (*io.SectionReader, error), entries map[string]tarEntry) ([]string, error) {
	if _, ok := entries["manifest.json"]; ok {
		var m []struct{ Layers []string }
		if err := readJSON(open, "manifest.json", &m); err != nil {
			return nil, err
		}
		if len(m) == 0 {
			return nil, errors.New("manifest.json lists no image")
		}
		return m[0].Layers, nil
	}
	if _, ok := entries["index.json"]; !ok {
		return nil, errors.New("no manifest.json or index.json; create the archive with: docker save IMAGE -o image.tar")
	}
	name := "index.json"
	for depth := 0; depth < 4; depth++ {
		var doc struct {
			Manifests []ociDescriptor `json:"manifests"`
			Layers    []ociDescriptor `json:"layers"`
		}
		if err := readJSON(open, name, &doc); err != nil {
			return nil, err
		}
		if len(doc.Layers) > 0 {
			var out []string
			for _, l := range doc.Layers {
				out = append(out, blobPath(l.Digest))
			}
			return out, nil
		}
		next := pickManifest(doc.Manifests)
		if next == "" {
			break
		}
		name = blobPath(next)
	}
	return nil, errors.New("no image manifest with layers in index.json")
}

// pickManifest takes the first image manifest, skipping attestations ("unknown" platform).
func pickManifest(ms []ociDescriptor) string {
	for _, m := range ms {
		if m.Platform == nil || m.Platform.OS != "unknown" {
			return m.Digest
		}
	}
	return ""
}

func layerReader(sr *io.SectionReader) (io.Reader, error) {
	magic := make([]byte, 4)
	n, _ := sr.ReadAt(magic, 0)
	switch {
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return gzip.NewReader(sr)
	case n == 4 && bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return nil, errors.New("zstd-compressed layers are not supported; save the image with docker save")
	}
	return sr, nil
}

// wantedFile says which image files feed the inventory; everything else is skipped unread.
func wantedFile(name string) bool {
	switch name {
	case "etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed":
		return true
	}
	if strings.HasPrefix(name, "var/lib/dpkg/status.d/") {
		return !strings.HasSuffix(name, ".md5sums")
	}
	for _, skip := range []string{"node_modules/", "vendor/", "testdata/", "proc/", "sys/"} {
		if strings.HasPrefix(name, skip) || strings.Contains(name, "/"+skip) {
			return false
		}
	}
	return IsLockfile(name)
}

func cleanName(n string) string {
	return strings.TrimPrefix(path.Clean("/"+n), "/")
}

// applyLayer updates files with one layer; whiteouts remove lower-layer files first.
func applyLayer(sr *io.SectionReader, files map[string][]byte) error {
	lr, err := layerReader(sr)
	if err != nil {
		return err
	}
	var removed, opaque []string
	added := map[string][]byte{}
	tr := tar.NewReader(lr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := cleanName(h.Name)
		dir, base := path.Split(name)
		switch {
		case base == ".wh..wh..opq":
			opaque = append(opaque, strings.TrimSuffix(dir, "/"))
		case strings.HasPrefix(base, ".wh."):
			removed = append(removed, dir+strings.TrimPrefix(base, ".wh."))
		case h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink:
			removed = append(removed, name) // a link now replaces any file here
		case h.Typeflag != tar.TypeReg:
		case wantedFile(name):
			if h.Size > maxImageFile {
				return fmt.Errorf("%s is larger than %d bytes", name, maxImageFile)
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			added[name] = b
		}
	}
	for _, d := range opaque {
		deletePrefix(files, d+"/")
	}
	for _, p := range removed {
		delete(files, p)
		deletePrefix(files, p+"/")
	}
	total := 0
	for _, b := range files {
		total += len(b)
	}
	for k, b := range added {
		total += len(b)
		files[k] = b
	}
	if total > maxImageTotal || len(files) > maxImageFiles {
		return errors.New("image holds more package metadata than the scan limit")
	}
	return nil
}

func deletePrefix(files map[string][]byte, prefix string) {
	for k := range files {
		if strings.HasPrefix(k, prefix) {
			delete(files, k)
		}
	}
}

func inventory(files map[string][]byte) *Image {
	img := &Image{}
	osr := files["etc/os-release"]
	if osr == nil {
		osr = files["usr/lib/os-release"]
	}
	img.OS = osEcosystem(osr)
	if img.OS == "" && osr != nil {
		img.Notes = append(img.Notes, "operating system not supported for OS package matching (Debian, Ubuntu and Alpine are)")
	}
	for name, b := range files {
		switch {
		case name == "var/lib/dpkg/status" || strings.HasPrefix(name, "var/lib/dpkg/status.d/"):
			img.Packages = append(img.Packages, parseDpkgStatus(b, img.OS, name)...)
		case name == "lib/apk/db/installed":
			img.Packages = append(img.Packages, parseApkInstalled(b, img.OS, name)...)
		case IsLockfile(name) && !shadowedGoSum(name, files):
			pkgs, err := ParseLockfile(name, b)
			if err != nil {
				img.Notes = append(img.Notes, fmt.Sprintf("%s: %v", name, err))
			}
			img.Packages = append(img.Packages, pkgs...)
		}
	}
	if img.OS == "" {
		img.Packages = dropOS(img.Packages)
	}
	return img
}

func shadowedGoSum(name string, files map[string][]byte) bool {
	if path.Base(name) != "go.sum" {
		return false
	}
	_, ok := files[path.Join(path.Dir(name), "go.mod")]
	return ok
}

func dropOS(pkgs []Package) []Package {
	out := pkgs[:0]
	for _, p := range pkgs {
		if p.Ecosystem != "" {
			out = append(out, p)
		}
	}
	return out
}

func osRelease(b []byte) map[string]string {
	kv := map[string]string{}
	eachLine(b, func(_ int, line string) {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	})
	return kv
}

func osEcosystem(b []byte) string {
	kv := osRelease(b)
	ver := kv["VERSION_ID"]
	if ver == "" {
		return ""
	}
	parts := strings.Split(ver, ".")
	switch kv["ID"] {
	case "debian":
		return "Debian:" + parts[0]
	case "ubuntu":
		return "Ubuntu:" + ver
	case "alpine":
		if len(parts) >= 2 {
			return "Alpine:v" + parts[0] + "." + parts[1]
		}
	}
	return ""
}

// stanzas splits RFC 822 style records (dpkg status, apk installed) by blank lines.
func stanzas(b []byte, sep string, fn func(line int, fields map[string]string)) {
	fields, start := map[string]string{}, 0
	flush := func() {
		if len(fields) > 0 {
			fn(start, fields)
		}
		fields = map[string]string{}
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of a long field
		}
		if k, v, ok := strings.Cut(line, sep); ok {
			if len(fields) == 0 {
				start = n
			}
			fields[k] = strings.TrimSpace(v)
		}
	}
	flush()
}

// parseDpkgStatus reports source packages, which is how OSV names Debian and Ubuntu advisories.
func parseDpkgStatus(b []byte, eco, file string) []Package {
	var out []Package
	stanzas(b, ":", func(line int, f map[string]string) {
		if st, ok := f["Status"]; ok && !strings.HasSuffix(st, " installed") {
			return
		}
		name, ver := f["Package"], f["Version"]
		if src := f["Source"]; src != "" {
			s, v, hasVer := strings.Cut(src, " ")
			name = s
			if hasVer {
				ver = strings.Trim(v, "() ")
			}
		}
		out = append(out, Package{Ecosystem: eco, Name: name, Version: ver, File: file, Line: line})
	})
	return out
}

func parseApkInstalled(b []byte, eco, file string) []Package {
	var out []Package
	stanzas(b, ":", func(line int, f map[string]string) {
		name := f["o"]
		if name == "" {
			name = f["P"]
		}
		out = append(out, Package{Ecosystem: eco, Name: name, Version: f["V"], File: file, Line: line})
	})
	return out
}
