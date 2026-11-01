package pulse

import (
	"strings"
	"testing"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

func module(t *testing.T, path, src, policy string) Module {
	t.Helper()
	cfg, err := engine.ParseConfig(policy)
	if err != nil {
		t.Fatal(err)
	}
	return Module{Path: path, Report: engine.Scan(engine.Input{Files: map[string]string{"main.tf": src}, Config: policy}), Config: cfg, HasPolicy: policy != ""}
}

const good = `terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket       = "state"
    key          = "x"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
resource "aws_sqs_queue" "q" {
  name = "q"
}
`

const bad = `resource "aws_db_instance" "db" {
  password            = "hunter2hunter2"
  publicly_accessible = true
}
`

func TestBuildAdoptionWaiversAndTrend(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	policy := `waivers:
  - {rule: TG-AWS-RDS-001, reason: legacy, expires: "2026-11-10", approved_by: sec}
  - {rule: TG-AWS-RDS-002, reason: old, expires: "2026-10-01"}
  - {rule: TG-AWS-RDS-003, reason: forever}
  - {rule: TG-SEC-001, reason: later, expires: "2027-06-01"}
`
	mods := []Module{module(t, "svc/good", good, ""), module(t, "svc/bad", bad, policy)}
	r := Build(mods, now, nil)

	adoption := map[string]int{}
	for _, a := range r.Adoption {
		adoption[a.ID] = a.Passing
	}
	if adoption["policy"] != 1 || adoption["pinned"] != 1 || adoption["state"] != 1 || adoption["applies"] != 2 {
		t.Fatalf("adoption = %v", adoption)
	}
	if r.Modules[0].Path != "svc/bad" {
		t.Fatalf("modules must be sorted worst first: %+v", r.Modules)
	}
	status := map[string]string{}
	for _, w := range r.Waivers {
		status[w.Rule] = w.Status
	}
	want := map[string]string{"TG-AWS-RDS-001": "expiring", "TG-AWS-RDS-002": "expired", "TG-AWS-RDS-003": "no-expiry", "TG-SEC-001": "active"}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("waiver %s = %q, want %q", k, status[k], v)
		}
	}
	if r.Waivers[0].Status != "expired" {
		t.Errorf("expired waivers must be listed first")
	}

	next := Build(mods[:1], now, r)
	if next.Delta == nil || next.Delta.AvgScore <= 0 || next.Delta.Findings >= 0 {
		t.Fatalf("delta = %+v", next.Delta)
	}
	md := Markdown(next)
	for _, s := range []string{"## TerraGuard Pulse", "Control adoption", "pts", "svc/good"} {
		if !strings.Contains(md, s) {
			t.Errorf("markdown missing %q", s)
		}
	}
}
