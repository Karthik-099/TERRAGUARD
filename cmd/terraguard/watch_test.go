package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFingerprintChangesOnEdit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "main.tf")
	os.WriteFile(p, []byte("a"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644)
	a := fingerprint([]string{dir})
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("xyz"), 0o644)
	if fingerprint([]string{dir}) != a {
		t.Error("files the scan does not read must not trigger a rerun")
	}
	os.Chtimes(p, time.Now().Add(time.Second), time.Now().Add(time.Second))
	os.WriteFile(p, []byte("ab"), 0o644)
	if fingerprint([]string{dir}) == a {
		t.Error("an edit must change the fingerprint")
	}
	if rest, ok := cutFlag([]string{".", "--watch", "--fail-on", "NONE"}, "--watch"); !ok || len(rest) != 3 {
		t.Errorf("cutFlag: %v %v", rest, ok)
	}
}
