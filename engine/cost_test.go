package engine

import (
	"strings"
	"testing"
)

func TestEstimateCost(t *testing.T) {
	plan := `{"resource_changes":[
  {"address":"aws_instance.web","mode":"managed","type":"aws_instance","change":{"actions":["update"],"before":{"instance_type":"t3.micro"},"after":{"instance_type":"m5.xlarge"}}},
  {"address":"aws_nat_gateway.a","mode":"managed","type":"aws_nat_gateway","change":{"actions":["create"],"before":null,"after":{}}},
  {"address":"aws_db_instance.db","mode":"managed","type":"aws_db_instance","change":{"actions":["delete"],"before":{"instance_class":"db.t3.micro","allocated_storage":20},"after":null}},
  {"address":"aws_ebs_volume.v","mode":"managed","type":"aws_ebs_volume","change":{"actions":["create"],"before":null,"after":{"size":100,"type":"gp3"}}},
  {"address":"aws_s3_bucket.b","mode":"managed","type":"aws_s3_bucket","change":{"actions":["create"],"before":null,"after":{}}}]}`
	c, err := EstimateCost(plan)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]float64{
		"aws_instance.web":   {0.0104 * 730, 0.192 * 730},
		"aws_nat_gateway.a":  {0, 0.045 * 730},
		"aws_db_instance.db": {0.0104*1.78*730 + 20*0.115, 0},
		"aws_ebs_volume.v":   {0, 8},
	}
	for _, l := range c.Lines {
		w, ok := want[l.Address]
		if !ok || abs(l.Before-w[0]) > 0.01 || abs(l.After-w[1]) > 0.01 {
			t.Errorf("%s: before %.2f after %.2f, want %.2f %.2f", l.Address, l.Before, l.After, w[0], w[1])
		}
		delete(want, l.Address)
	}
	if len(want) != 0 {
		t.Errorf("not priced: %v", want)
	}
	if len(c.Unpriced) != 1 || c.Unpriced[0] != "aws_s3_bucket" {
		t.Errorf("usage-priced types must be listed as unpriced: %v", c.Unpriced)
	}
	if md := CostMarkdown(c); !strings.Contains(md, "+$") || !strings.Contains(md, "us-east-1") {
		t.Errorf("markdown: %s", md)
	}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func TestCostAzureGCPUsageAndOverrides(t *testing.T) {
	plan := `{"resource_changes":[
  {"address":"azurerm_linux_virtual_machine.vm","mode":"managed","type":"azurerm_linux_virtual_machine","change":{"actions":["create"],"before":null,"after":{"size":"Standard_D4s_v5"}}},
  {"address":"google_compute_instance.g","mode":"managed","type":"google_compute_instance","change":{"actions":["create"],"before":null,"after":{"machine_type":"e2-standard-4"}}},
  {"address":"aws_lambda_function.f","mode":"managed","type":"aws_lambda_function","change":{"actions":["create"],"before":null,"after":{"memory_size":1024}}},
  {"address":"aws_nat_gateway.n","mode":"managed","type":"aws_nat_gateway","change":{"actions":["create"],"before":null,"after":{}}}]}`
	usage := "resource_usage:\n  aws_lambda_function.f:\n    monthly_requests: 10000000\n    request_duration_ms: 100\n"
	c, err := EstimateCostWith(plan, CostOptions{Usage: usage, Prices: "aws.nat_gateway.hour: 0.05\n"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, l := range c.Lines {
		got[l.Address] = l.After
	}
	want := map[string]float64{
		"azurerm_linux_virtual_machine.vm": 0.048 * 4 * 730,
		"google_compute_instance.g":        (0.021811*4 + 0.002923*16) * 730,
		"aws_lambda_function.f":            10*0.20 + 1e7*0.1*1*0.0000166667,
		"aws_nat_gateway.n":                0.05 * 730,
	}
	for a, w := range want {
		if abs(got[a]-w) > 0.02 {
			t.Errorf("%s = %.2f, want %.2f", a, got[a], w)
		}
	}
	if _, err := EstimateCostWith(plan, CostOptions{Usage: "resource_usage: [1"}); err == nil {
		t.Error("a broken usage file is an error")
	}
	code := map[string]string{"main.tf": "resource \"aws_instance\" \"a\" {\n  instance_type = \"t3.micro\"\n}\nresource \"aws_instance\" \"b\" {\n  instance_type = var.size\n}\n"}
	fc, err := EstimateCostFromCode(code, CostOptions{})
	if err != nil || len(fc.Lines) != 1 || abs(fc.After-0.0104*730) > 0.01 || len(fc.Unpriced) != 1 {
		t.Errorf("from code: %+v %v", fc, err)
	}
}
