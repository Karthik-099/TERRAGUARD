package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

var scanCacheMax int64 = 200 << 20 // bytes; the oldest entries go first

// scanCacheKey hashes everything engine.Scan reads. The whole input is one key, not
// one per directory: module inputs, attack paths, CODEOWNERS, waivers and the gate cross directories.
func scanCacheKey(in engine.Input) string {
	h := sha256.New()
	// Waiver and ignore expiry compare against the UTC day, so the day is an input too.
	json.NewEncoder(h).Encode([]string{engine.Version, engine.RulesVersion, time.Now().UTC().Format("2006-01-02")})
	json.NewEncoder(h).Encode(in) // map keys are sorted: file paths and contents in a fixed order
	return hex.EncodeToString(h.Sum(nil))
}

func scanCacheDir() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	d = filepath.Join(d, "terraguard", "scan-cache")
	return d, os.MkdirAll(d, 0o700)
}

// cachedScan is engine.Scan with an on-disk result cache. Any cache error
// falls back to a normal scan: the cache can only save time, never change a result.
func cachedScan(in engine.Input, enabled bool) *engine.Report {
	if !enabled {
		return engine.Scan(in)
	}
	dir, err := scanCacheDir()
	if err != nil {
		return engine.Scan(in)
	}
	file := filepath.Join(dir, scanCacheKey(in)+".json")
	if b, err := os.ReadFile(file); err == nil {
		var rep engine.Report
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber() // fix values keep their exact JSON form
		if d.Decode(&rep) == nil {
			now := time.Now()
			os.Chtimes(file, now, now)
			return &rep
		}
	}
	rep := engine.Scan(in)
	if b, err := json.Marshal(rep); err == nil {
		writeCacheEntry(dir, file, b)
	}
	return rep
}

// writeCacheEntry writes atomically with mode 0600, then trims the folder to scanCacheMax.
func writeCacheEntry(dir, file string, b []byte) {
	tmp, err := os.CreateTemp(dir, ".tmp-*") // CreateTemp uses 0600
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr != nil || cerr != nil || os.Rename(tmp.Name(), file) != nil {
		os.Remove(tmp.Name())
		return
	}
	ents, _ := os.ReadDir(dir)
	type entry struct {
		path string
		size int64
		mod  time.Time
	}
	var all []entry
	var total int64
	for _, e := range ents {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			all = append(all, entry{filepath.Join(dir, e.Name()), info.Size(), info.ModTime()})
			total += info.Size()
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod.Before(all[j].mod) })
	for _, e := range all {
		if total <= scanCacheMax {
			break
		}
		if os.Remove(e.path) == nil {
			total -= e.size
		}
	}
}

// scanCacheOn reports whether --cache or TERRAGUARD_CACHE=true turns the cache on.
func scanCacheOn(flag bool) bool {
	return flag || os.Getenv("TERRAGUARD_CACHE") == "true"
}
