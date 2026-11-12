package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyExtendsStaysInsideWorkingFolder(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	os.WriteFile(secret, []byte("TOPSECRETVALUE"), 0o600)
	work := t.TempDir()
	t.Chdir(work)
	os.MkdirAll("org", 0o755)
	os.WriteFile("org/base.yml", []byte("fail_on: HIGH\n"), 0o600)
	os.WriteFile("notpolicy.txt", []byte("TOPSECRETVALUE"), 0o600)

	if _, err := resolvePolicy("extends: [org/base.yml]\n", "."); err != nil {
		t.Fatalf("relative policy inside the folder: %v", err)
	}
	rel, _ := filepath.Rel(work, secret)
	for _, ref := range []string{secret, rel, "/proc/self/environ", "notpolicy.txt", "file:///etc/passwd"} {
		_, err := resolvePolicy("extends: ["+ref+"]\n", ".")
		if err == nil {
			t.Errorf("extends %s: want an error", ref)
		} else if strings.Contains(err.Error(), "TOPSECRETVALUE") {
			t.Errorf("extends %s: error leaks file content", ref)
		}
	}
	t.Setenv("TERRAGUARD_OFFLINE", "true")
	if _, err := resolvePolicy("extends: [https://example.com/p.yml]\n", "."); err == nil || !strings.Contains(err.Error(), "OFFLINE") {
		t.Errorf("offline mode must refuse remote policies, got %v", err)
	}
}
