package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderManifests(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "chart", "templates"), 0o755)
	os.WriteFile(filepath.Join(dir, "chart", "Chart.yaml"), []byte("name: x\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "overlay"), 0o755)
	os.WriteFile(filepath.Join(dir, "overlay", "kustomization.yaml"), []byte("resources: []\n"), 0o644)
	var calls []string
	runRender = func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n", nil
	}
	t.Cleanup(func() { runRender = nil })
	got, err := renderManifests([]string{dir}, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(calls) != 2 || !strings.HasPrefix(calls[0], "helm template terraguard ") && !strings.HasPrefix(calls[1], "helm template terraguard ") {
		t.Errorf("rendered %v with calls %v", got, calls)
	}
}
