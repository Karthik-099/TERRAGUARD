package engine

import "testing"

func TestDABDetection(t *testing.T) {
	for name, want := range map[string]string{
		"databricks.yml":            "resources: {}\n",
		"bundle/databricks.yaml":    "bundle:\n  name: x\n",
		"resources/etl.job.yml":     "# a job\nresources:\n  jobs:\n    etl:\n      name: etl\n",
		"resources/p.pipeline.yaml": "resources:\n\n  pipelines:\n    p: {}\n",
	} {
		if f := detectFormat(name, want); f != FormatDAB {
			t.Errorf("detectFormat(%s) = %q, want %q", name, f, FormatDAB)
		}
	}
	for name, src := range map[string]string{
		"values.yaml": "resources:\n  limits:\n    cpu: 1\n",
		"ci.yml":      "resources:\n- name: repo\njobs:\n- name: build\n",
	} {
		if f := detectFormat(name, src); f == FormatDAB {
			t.Errorf("detectFormat(%s) = %q", name, f)
		}
	}
}

func TestDABVariables(t *testing.T) {
	src := `variables:
  same: {default: NONE}
  differs: {default: NONE}
  lookedup: {lookup: {cluster: shared}}
  cluster:
    type: complex
    default:
      spark_version: 15.4.x-scala2.12
      autotermination_minutes: 0
targets:
  dev: {variables: {same: NONE, differs: NONE}}
  prod: {variables: {differs: USER_ISOLATION}}
resources:
  clusters:
    a: {data_security_mode: "${var.same}", autotermination_minutes: "${var.lookedup}"}
    b: {data_security_mode: "${var.differs}"}
    c: {data_security_mode: "${bundle.target}"}
  jobs:
    j:
      job_clusters:
        - job_cluster_key: k
          new_cluster: ${var.cluster}
`
	rs, syntax := parseDAB("databricks.yml", src)
	if len(syntax) != 0 || len(rs) != 4 {
		t.Fatalf("want 4 resources, got %d (%v)", len(rs), syntax)
	}
	by := map[string]*Resource{}
	for _, r := range rs {
		by[r.Address] = r
	}
	if v := by["databricks_cluster.a"].get("data_security_mode"); v != "NONE" || by["databricks_cluster.a"].via("data_security_mode") != "var.same" {
		t.Errorf("same value in every target should resolve, got %v", v)
	}
	for _, k := range []string{"databricks_cluster.b", "databricks_cluster.c"} {
		if !isUnknown(by[k].get("data_security_mode")) {
			t.Errorf("%s: want unknown, got %v", k, by[k].get("data_security_mode"))
		}
	}
	if !isUnknown(by["databricks_cluster.a"].get("autotermination_minutes")) {
		t.Error("lookup variables are decided at deploy time")
	}
	if v := by["databricks_job.j"].get("job_cluster.0.new_cluster.0.autotermination_minutes"); v != 0.0 {
		t.Errorf("complex variable not resolved: %v", v)
	}
	if l := by["databricks_job.j"].line("job_cluster.0.new_cluster"); l != 22 {
		t.Errorf("new_cluster line = %d, want 22", l)
	}
}
