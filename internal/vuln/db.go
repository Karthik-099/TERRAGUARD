package vuln

import (
	"archive/zip"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultEcosystems are downloaded when update is given no list.
var DefaultEcosystems = []string{"Go", "npm", "PyPI", "Maven", "RubyGems", "crates.io", "Packagist", "NuGet", "Debian", "Alpine", "Ubuntu"}

// BaseURL is the public OSV bucket; <BaseURL>/<Ecosystem>/all.zip.
const BaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

const (
	maxDownload = 4 << 30  // the largest ecosystem zips are a few hundred MB
	maxRecord   = 16 << 20 // one OSV JSON record
)

// ErrNoDatabase means update has not been run for the directory.
var ErrNoDatabase = errors.New("no vulnerability database; run terraguard vuln update")

// Meta describes a downloaded database.
type Meta struct {
	Updated    time.Time                 `json:"updated"`
	Ecosystems map[string]EcosystemStats `json:"ecosystems"`
}

// EcosystemStats counts what one ecosystem's index holds.
type EcosystemStats struct {
	Records  int       `json:"records"`
	Packages int       `json:"packages"`
	Updated  time.Time `json:"updated"`
}

// index maps an OSV ecosystem ("Debian:12") and package name to entries.
type index map[string]map[string][]Entry

// DefaultDir is the cache directory used when --db is not given.
func DefaultDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "terraguard", "osv")
}

var ecosystemName = regexp.MustCompile(`^[A-Za-z0-9.:_ -]+$`) // spaces: "Red Hat", "Rocky Linux"

// Update downloads and indexes each ecosystem. It is the only network access.
func Update(ctx context.Context, dir string, ecosystems []string, log io.Writer) error {
	if os.Getenv("TERRAGUARD_OFFLINE") == "true" {
		return errors.New("vuln update refused: TERRAGUARD_OFFLINE=true (copy a database made on a connected machine instead)")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	meta, _ := readMeta(dir)
	client := &http.Client{Timeout: 30 * time.Minute, CheckRedirect: httpsOnly}
	for _, eco := range ecosystems {
		if !ecosystemName.MatchString(eco) || strings.Contains(eco, "..") {
			return fmt.Errorf("invalid ecosystem %q", eco)
		}
		start := time.Now()
		stats, err := updateOne(ctx, client, dir, eco)
		if err != nil {
			return fmt.Errorf("%s: %w", eco, err)
		}
		meta.Ecosystems[eco] = stats
		fmt.Fprintf(log, "%-10s %7d records, %6d packages (%s)\n", eco, stats.Records, stats.Packages, time.Since(start).Round(time.Second))
	}
	meta.Updated = time.Now().UTC()
	b, _ := json.MarshalIndent(meta, "", "  ")
	return writeAtomic(filepath.Join(dir, "meta.json"), func(w io.Writer) error { _, err := w.Write(b); return err })
}

// httpsOnly keeps a redirect from downgrading the download to plain HTTP.
func httpsOnly(r *http.Request, via []*http.Request) error {
	if r.URL.Scheme != "https" || len(via) > 5 {
		return fmt.Errorf("refusing redirect to %s", r.URL.Redacted())
	}
	return nil
}

func updateOne(ctx context.Context, client *http.Client, dir, eco string) (EcosystemStats, error) {
	tmp, err := os.CreateTemp(dir, eco+"-*.zip")
	if err != nil {
		return EcosystemStats{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL+"/"+url.PathEscape(eco)+"/all.zip", nil)
	if err != nil {
		return EcosystemStats{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return EcosystemStats{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return EcosystemStats{}, fmt.Errorf("download: %s", resp.Status)
	}
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return EcosystemStats{}, err
	}
	if n > maxDownload {
		return EcosystemStats{}, fmt.Errorf("download is larger than %d bytes", maxDownload)
	}
	return IndexZip(tmp.Name(), dir, eco)
}

// IndexZip turns an OSV all.zip into the gob index for one ecosystem.
func IndexZip(zipPath, dir, eco string) (EcosystemStats, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return EcosystemStats{}, fmt.Errorf("not a valid zip: %w", err)
	}
	defer zr.Close()
	idx := index{}
	stats := EcosystemStats{Updated: time.Now().UTC()}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if f.UncompressedSize64 > maxRecord {
			return stats, fmt.Errorf("%s: record larger than %d bytes", f.Name, maxRecord)
		}
		rec, err := readRecord(f)
		if err != nil {
			return stats, fmt.Errorf("%s: %w", f.Name, err)
		}
		if rec.Withdrawn != "" {
			continue
		}
		stats.Records++
		addRecord(idx, rec)
	}
	for _, pkgs := range idx {
		stats.Packages += len(pkgs)
	}
	return stats, writeAtomic(filepath.Join(dir, eco+".gob"), func(w io.Writer) error { return gob.NewEncoder(w).Encode(idx) })
}

func readRecord(f *zip.File) (*osvRecord, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var rec osvRecord
	if err := json.NewDecoder(io.LimitReader(rc, maxRecord)).Decode(&rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func addRecord(idx index, rec *osvRecord) {
	for i, a := range rec.Affected {
		eco := a.Package.Ecosystem
		if eco == "" || a.Package.Name == "" {
			continue
		}
		if idx[eco] == nil {
			idx[eco] = map[string][]Entry{}
		}
		name := normName(eco, a.Package.Name)
		summary := rec.Summary
		if summary == "" {
			summary, _, _ = strings.Cut(strings.TrimSpace(rec.Details), "\n")
		}
		versions := a.Versions
		if hasVersionRange(a.Ranges) {
			// shortcut: drop the enumerated list when a version range covers it (it is
			// usually generated from the range); it is most of the Debian index size.
			versions = nil
		}
		idx[eco][name] = append(idx[eco][name], Entry{
			ID: rec.ID, Aliases: rec.Aliases, Summary: truncate(summary, 200),
			Severity: severityOf(rec, i), Ranges: a.Ranges, Versions: versions,
		})
	}
}

func hasVersionRange(rs []Range) bool {
	for _, r := range rs {
		if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// normName applies each ecosystem's case and separator rules so lockfiles and OSV agree.
func normName(eco, name string) string {
	switch baseEcosystem(eco) {
	case "PyPI":
		return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
	case "NuGet", "Packagist":
		return strings.ToLower(name)
	}
	return name
}

func writeAtomic(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readMeta(dir string) (Meta, error) {
	m := Meta{Ecosystems: map[string]EcosystemStats{}}
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	if m.Ecosystems == nil {
		m.Ecosystems = map[string]EcosystemStats{}
	}
	return m, err
}

// DB reads indexes lazily, one ecosystem file at a time.
type DB struct {
	Dir  string
	Meta Meta
	idx  map[string]index
}

// Open checks that update has run for dir.
func Open(dir string) (*DB, error) {
	meta, err := readMeta(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w (looked in %s)", ErrNoDatabase, dir)
		}
		return nil, err
	}
	return &DB{Dir: dir, Meta: meta, idx: map[string]index{}}, nil
}

// MissingEcosystemError names an ecosystem the scan needs but update did not fetch.
type MissingEcosystemError struct{ Ecosystem string }

func (e *MissingEcosystemError) Error() string {
	return fmt.Sprintf("the database has no %s data; run terraguard vuln update --ecosystems %s", e.Ecosystem, e.Ecosystem)
}

// Lookup returns the entries for a package. Ubuntu and Red Hat ecosystems also
// match their suffixed forms ("Ubuntu:22.04" matches "Ubuntu:22.04:LTS",
// "Red Hat:enterprise_linux:9" matches "Red Hat:enterprise_linux:9::baseos").
func (db *DB) Lookup(eco, name string) ([]Entry, error) {
	base := baseEcosystem(eco)
	idx, ok := db.idx[base]
	if !ok {
		f, err := os.Open(filepath.Join(db.Dir, base+".gob"))
		if errors.Is(err, os.ErrNotExist) {
			return nil, &MissingEcosystemError{base}
		}
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := gob.NewDecoder(f).Decode(&idx); err != nil {
			return nil, fmt.Errorf("%s index is corrupt, run terraguard vuln update: %w", base, err)
		}
		db.idx[base] = idx
	}
	name = normName(eco, name)
	out := idx[eco][name]
	if base == "Ubuntu" || base == "Red Hat" {
		for e, pkgs := range idx {
			if strings.HasPrefix(e, eco+":") {
				out = append(out, pkgs[name]...)
			}
		}
	}
	return out, nil
}
