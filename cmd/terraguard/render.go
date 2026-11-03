package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// renderManifests renders Helm charts and Kustomize overlays into plain
// manifests and Bicep files into ARM templates, so the rules check what would
// be deployed. It runs the helm, kustomize (or kubectl) and bicep (or az)
// binaries, so it is opt-in.
func renderManifests(paths []string, helm, kustomize, bicep bool) (map[string]string, error) {
	out := map[string]string{}
	for _, root := range paths {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			if d.IsDir() {
				return nil
			}
			dir := filepath.Dir(p)
			switch {
			case helm && d.Name() == "Chart.yaml":
				yaml, err := runRender("helm", "template", "terraguard", dir)
				if err != nil {
					return fmt.Errorf("helm template %s: %w", dir, err)
				}
				out[filepath.ToSlash(filepath.Join(dir, "helm-rendered.yaml"))] = yaml
				return filepath.SkipDir // templates are not manifests on their own
			case bicep && strings.HasSuffix(d.Name(), ".bicep"):
				json, err := runRender("bicep", "build", p, "--stdout")
				if errors.Is(err, exec.ErrNotFound) {
					json, err = runRender("az", "bicep", "build", "--file", p, "--stdout")
				}
				if err != nil {
					return fmt.Errorf("bicep build %s: %w", p, err)
				}
				out[filepath.ToSlash(strings.TrimSuffix(p, ".bicep")+".bicep.json")] = json
			case kustomize && (d.Name() == "kustomization.yaml" || d.Name() == "kustomization.yml"):
				yaml, err := runRender("kustomize", "build", dir)
				if errors.Is(err, exec.ErrNotFound) {
					yaml, err = runRender("kubectl", "kustomize", dir)
				}
				if err != nil {
					return fmt.Errorf("kustomize build %s: %w", dir, err)
				}
				out[filepath.ToSlash(filepath.Join(dir, "kustomize-rendered.yaml"))] = yaml
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// runRender is replaced in tests.
var runRender = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "HELM_NO_PLUGINS=1")
	b, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(b), nil
}
