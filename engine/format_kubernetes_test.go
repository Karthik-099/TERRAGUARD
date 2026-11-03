package engine

import (
	"strings"
	"testing"
)

func TestKubernetesManifestShape(t *testing.T) {
	src := `apiVersion: v1
kind: List
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: web
    namespace: shop
    labels: {app: web}
  spec:
    selector:
      matchLabels: {app: web}
    template:
      spec:
        hostPID: true
        securityContext:
          runAsUser: 1000
        initContainers:
        - name: init
          image: busybox:1.36
        containers:
        - name: web
          image: "{{ .Values.image }}"
          resources:
            limits: {memory: 256Mi}
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  selector: {app: web}
  externalIPs: [10.0.0.1]
`
	rs, syntax := parseKubernetes("m.yaml", src)
	if len(syntax) != 0 || len(rs) != 2 {
		t.Fatalf("got %d resources, %v", len(rs), syntax)
	}
	d, s := rs[0], rs[1]
	if d.Address != "Deployment.shop.web" || d.Type != "kubernetes_deployment_v1" || s.Address != "Service.default.web" || s.Type != "kubernetes_service_v1" {
		t.Fatalf("addresses: %s %s %s %s", d.Address, d.Type, s.Address, s.Type)
	}
	checks := map[string]any{
		"spec.0.template.0.spec.0.host_pid":                              true,
		"spec.0.template.0.spec.0.security_context.0.run_as_user":        "1000",
		"spec.0.template.0.spec.0.init_container.0.name":                 "init",
		"spec.0.template.0.spec.0.container.0.resources.0.limits.memory": "256Mi",
		"spec.0.selector.0.match_labels.app":                             "web",
		"metadata.0.labels.app":                                          "web",
	}
	for p, want := range checks {
		if got := d.get(p); got != want {
			t.Errorf("%s = %#v, want %#v", p, got, want)
		}
	}
	if !isUnknown(d.get("spec.template.spec.container.image")) {
		t.Error("a template placeholder should be unknown")
	}
	if s.get("spec.selector.app") != "web" || s.get("spec.external_ips") == nil {
		t.Errorf("service shape: %#v", s.Attrs)
	}
	if l := d.line("spec.0.template.0.spec.0.host_pid"); l != 15 {
		t.Errorf("host_pid line %d, want 15", l)
	}
	if d.Line != 4 {
		t.Errorf("resource line %d, want 4", d.Line)
	}
}

func TestKubernetesManifestRules(t *testing.T) {
	src := `apiVersion: v1
kind: Pod
metadata: {name: kube-apiserver, namespace: kube-system}
spec:
  containers:
  - name: api
    image: registry.k8s.io/kube-apiserver:v1.30.0
    command: [kube-apiserver, --authorization-mode=AlwaysAllow]
`
	got := map[string]bool{}
	for _, f := range Scan(Input{Files: map[string]string{"api.yaml": src}}).Findings {
		got[f.RuleID] = true
	}
	if !got["TG-K8S-API-407"] || !got["TG-K8S-009"] {
		t.Errorf("flag and container rules should run on manifests: %v", got)
	}
	// Scan skips templated files; the parser still marks placeholders unknown.
	rs, _ := parseKubernetes("api.yaml", strings.Replace(src, "]", `, "--anonymous-auth={{ .Values.anon }}"]`, 1))
	for _, r := range Rules {
		if r.ID == "TG-K8S-API-407" || r.ID == "TG-K8S-API-401" {
			if hits := r.Check(rs[0]); len(hits) > 0 {
				t.Errorf("%s fired with an unknown argument", r.ID)
			}
		}
	}
}

func TestK8sSnake(t *testing.T) {
	for in, want := range map[string]string{"hostPID": "host_pid", "runAsNonRoot": "run_as_non_root", "externalIPs": "external_ips", "hostIP": "host_ip", "seLinuxOptions": "se_linux_options"} {
		if got := k8sSnake(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}
