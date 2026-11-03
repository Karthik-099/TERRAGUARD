package engine

import (
	"strings"
	"testing"
)

func TestFixKubernetesManifestKeepsComments(t *testing.T) {
	src := `# web deployment, owned by the platform team
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web # public site
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: sidecar
          image: busybox:1.36
        - name: web
          image: nginx:1.27
          securityContext:
            allowPrivilegeEscalation: true # needed? no
`
	files := map[string]string{"deploy.yaml": src}
	out, errs := FixAll(Input{Files: files})
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	got := out["deploy.yaml"]
	for _, want := range []string{"# web deployment, owned by the platform team", "name: web # public site", "hostNetwork: false", "allowPrivilegeEscalation: false", "# needed? no"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Count(got, "allowPrivilegeEscalation") != 1 {
		t.Errorf("only the web container had the setting:\n%s", got)
	}
	again := Scan(Input{Files: map[string]string{"deploy.yaml": got}})
	for _, f := range again.Findings {
		if f.RuleID == "TG-K8S-001" {
			t.Errorf("fixed manifest still has %s: %s", f.RuleID, f.Message)
		}
	}
}

func TestFixDockerfileLines(t *testing.T) {
	src := "FROM alpine:3.20\nMAINTAINER Jane Doe <jane@example.com>\nADD app.py /app/app.py\nADD https://example.com/x.tgz /tmp/\n"
	out, _ := FixAll(Input{Files: map[string]string{"Dockerfile": src}})
	got := out["Dockerfile"]
	if !strings.Contains(got, `LABEL org.opencontainers.image.authors="Jane Doe <jane@example.com>"`) || !strings.Contains(got, "COPY app.py /app/app.py") {
		t.Errorf("fixed:\n%s", got)
	}
	if !strings.Contains(got, "ADD https://example.com/x.tgz") {
		t.Error("a URL source must stay ADD")
	}
	if _, err := applyLineEdit("FROM x\n", &Fix{Line: 1, Old: "ADD ", New: "COPY "}); err == nil {
		t.Error("an edit whose line changed must be refused")
	}
}
