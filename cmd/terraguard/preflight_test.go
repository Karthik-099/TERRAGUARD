package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

const preflightPlan = `{"format_version":"1.2",
 "configuration":{"provider_config":{"aws":{"name":"aws","expressions":{"region":{"constant_value":"eu-west-1"}}}}},
 "resource_changes":[
  {"address":"aws_instance.app[0]","mode":"managed","type":"aws_instance","change":{"actions":["create"],"after":{"instance_type":"m5.2xlarge"}}},
  {"address":"aws_instance.app[1]","mode":"managed","type":"aws_instance","change":{"actions":["create"],"after":{"instance_type":"m5.2xlarge"}}},
  {"address":"aws_vpc.main","mode":"managed","type":"aws_vpc","change":{"actions":["create"],"after":{}}},
  {"address":"aws_s3_bucket.logs","mode":"managed","type":"aws_s3_bucket","change":{"actions":["create"],"after":{"bucket":"logs"}}},
  {"address":"aws_s3_bucket.mine","mode":"managed","type":"aws_s3_bucket","change":{"actions":["create"],"after":{"bucket":"acme-unique-7f3a"}}}]}`

func TestPreflightLiveQuotas(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	os.WriteFile(plan, []byte(preflightPlan), 0o644)

	var calls []string
	runCLI = func(name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		switch {
		case strings.Contains(call, "get-service-quota") && strings.Contains(call, "L-1216C47A"):
			return []byte("24\n"), nil
		case strings.Contains(call, "get-service-quota") && strings.Contains(call, "L-F678F1CE"):
			return []byte("5\n"), nil
		case strings.Contains(call, "describe-instances"):
			// 12 standard vCPUs running; the GPU instance does not count.
			return []byte(`[["m5.2xlarge",4,2],["t3.medium",1,2],["c5.large",1,2],["g5.xlarge",2,2]]`), nil
		case strings.Contains(call, "describe-vpcs"):
			return []byte("2\n"), nil
		case strings.Contains(call, "head-bucket --bucket logs"):
			return nil, errors.New("aws: An error occurred (403) when calling the HeadBucket operation: Forbidden")
		case strings.Contains(call, "head-bucket"):
			return nil, errors.New("aws: An error occurred (404) when calling the HeadBucket operation: Not Found")
		case strings.Contains(call, "get-service-quota") && strings.Contains(call, "L-DC2B2D3D"):
			return []byte("10000\n"), nil
		case strings.Contains(call, "list-buckets"):
			return []byte("3\n"), nil
		case strings.Contains(call, "get-caller-identity"):
			return []byte("arn:aws:sts::123456789012:assumed-role/ci-deploy/run-42\n"), nil
		case strings.Contains(call, "iam get-role --role-name ci-deploy"):
			return []byte("arn:aws:iam::123456789012:role/platform/ci-deploy\n"), nil
		case strings.Contains(call, "simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:role/platform/ci-deploy"):
			return []byte(`{"EvaluationResults":[{"EvalActionName":"ec2:RunInstances","EvalDecision":"allowed"},{"EvalActionName":"ec2:CreateVpc","EvalDecision":"implicitDeny"},{"EvalActionName":"s3:CreateBucket","EvalDecision":"allowed"}]}`), nil
		}
		t.Fatalf("unexpected call: %s", call)
		return nil, nil
	}
	t.Cleanup(func() { runCLI = nil })

	out := filepath.Join(dir, "report.md")
	code, err := runPreflight([]string{"--plan", plan, "--live", "--markdown", out})
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 { // limit 24, 12 standard vCPUs running, 16 needed
		t.Fatalf("exit code %d, want 1 when a quota would be exceeded", code)
	}
	md, _ := os.ReadFile(out)
	for _, want := range []string{"| EXCEEDS | Running On-Demand Standard instances (vCPUs)", "| OK | VPCs per Region", "| TAKEN | logs |", "| FREE | acme-unique-7f3a |", "| ec2:CreateVpc | implicitDeny | aws_vpc.main |", "| ec2:RunInstances | allowed |"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report misses %q:\n%s", want, md)
		}
	}
	for _, c := range calls {
		if verb := strings.Fields(c); len(verb) > 2 && (strings.HasPrefix(verb[2], "create") || strings.HasPrefix(verb[2], "delete") || strings.HasPrefix(verb[2], "modify") || strings.HasPrefix(verb[2], "put-")) {
			t.Errorf("preflight made a non-read call: %s", c)
		}
	}
}

func TestPreflightQuotasFile(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	os.WriteFile(plan, []byte(preflightPlan), 0o644)
	quotas := filepath.Join(dir, "quotas.json")
	os.WriteFile(quotas, []byte(`{"aws/ec2/L-1216C47A@eu-west-1":{"limit":64,"used":10},"aws/vpc/L-F678F1CE@eu-west-1":{"limit":5,"used":1}}`), 0o644)
	if code, err := runPreflight([]string{"--plan", plan, "--quotas", quotas, "--format", "json"}); err != nil || code != 0 {
		t.Fatalf("enough quota left: code %d, err %v", code, err)
	}
}

func TestPreflightImplicitDenyNeedsStrict(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	os.WriteFile(plan, []byte(`{"format_version":"1.2",
 "configuration":{"provider_config":{"aws":{"name":"aws","expressions":{"region":{"constant_value":"eu-west-1"}}}}},
 "resource_changes":[{"address":"aws_vpc.main","mode":"managed","type":"aws_vpc","change":{"actions":["create"],"after":{}}}]}`), 0o644)
	decision := "implicitDeny"
	runCLI = func(name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(call, "get-service-quota"):
			return []byte("5\n"), nil
		case strings.Contains(call, "describe-vpcs"):
			return []byte("1\n"), nil
		case strings.Contains(call, "get-caller-identity"):
			return []byte("arn:aws:iam::123456789012:user/ci\n"), nil
		case strings.Contains(call, "simulate-principal-policy"):
			return []byte(`{"EvaluationResults":[{"EvalActionName":"ec2:CreateVpc","EvalDecision":"` + decision + `"}]}`), nil
		}
		t.Fatalf("unexpected call: %s", call)
		return nil, nil
	}
	t.Cleanup(func() { runCLI = nil })

	for _, c := range []struct {
		decision string
		strict   bool
		want     int
	}{{"implicitDeny", false, 0}, {"implicitDeny", true, 1}, {"explicitDeny", false, 1}} {
		decision = c.decision
		args := []string{"--plan", plan, "--live", "--format", "json"}
		if c.strict {
			args = append(args, "--strict-permissions")
		}
		if code, err := runPreflight(args); err != nil || code != c.want {
			t.Errorf("%s strict=%v: code %d err %v, want %d", c.decision, c.strict, code, err, c.want)
		}
	}
}

func TestPreflightRejectsFlagLikePlanValues(t *testing.T) {
	runCLI = func(name string, args ...string) ([]byte, error) {
		t.Fatalf("must not call the CLI with %v", args)
		return nil, nil
	}
	t.Cleanup(func() { runCLI = nil })
	if s := bucketStatus("--endpoint-url=http://evil"); s != "unknown" {
		t.Errorf("status %q", s)
	}
	if _, err := liveUsage(engine.QuotaDemand{Cloud: "aws", Region: "--endpoint-url=x", Quota: "ec2/L-1216C47A"}); err == nil {
		t.Error("flag-like region must be rejected")
	}
}
