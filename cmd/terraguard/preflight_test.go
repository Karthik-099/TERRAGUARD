package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	for _, want := range []string{"| EXCEEDS | Running On-Demand Standard instances (vCPUs)", "| OK | VPCs per Region", "| TAKEN | logs |", "| FREE | acme-unique-7f3a |"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report misses %q:\n%s", want, md)
		}
	}
	for _, c := range calls {
		if strings.Contains(c, "create") || strings.Contains(c, "delete") || strings.Contains(c, "modify") || strings.Contains(c, "put-") {
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
