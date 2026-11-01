package engine

import "testing"

const quotaPlanJSON = `{"format_version":"1.2",
 "configuration":{"provider_config":{"aws":{"name":"aws","expressions":{"region":{"constant_value":"eu-west-1"}}}}},
 "resource_changes":[
  {"address":"aws_instance.web[0]","mode":"managed","type":"aws_instance","change":{"actions":["create"],"after":{"instance_type":"m5.2xlarge"}}},
  {"address":"aws_instance.web[1]","mode":"managed","type":"aws_instance","change":{"actions":["create"],"after":{"instance_type":"t3.micro"}}},
  {"address":"aws_instance.gpu","mode":"managed","type":"aws_instance","change":{"actions":["create"],"after":{"instance_type":"g5.xlarge"}}},
  {"address":"aws_instance.grow","mode":"managed","type":"aws_instance","change":{"actions":["update"],"before":{"instance_type":"m5.large"},"after":{"instance_type":"m5.xlarge"}}},
  {"address":"aws_vpc.main","mode":"managed","type":"aws_vpc","change":{"actions":["create"],"after":{}}},
  {"address":"aws_eip.nat","mode":"managed","type":"aws_eip","change":{"actions":["create"],"after":{}}},
  {"address":"aws_lb.nlb","mode":"managed","type":"aws_lb","change":{"actions":["create"],"after":{"load_balancer_type":"network"}}},
  {"address":"aws_lb.web","mode":"managed","type":"aws_lb","change":{"actions":["create"],"after":{"load_balancer_type":"application"}}},
  {"address":"aws_vpc.kept","mode":"managed","type":"aws_vpc","change":{"actions":["no-op"],"after":{}}},
  {"address":"azurerm_linux_virtual_machine.vm","mode":"managed","type":"azurerm_linux_virtual_machine","change":{"actions":["create"],"after":{"size":"Standard_D4s_v5","location":"West Europe"}}},
  {"address":"google_compute_instance.vm","mode":"managed","type":"google_compute_instance","change":{"actions":["create"],"after":{"machine_type":"n2-standard-8","zone":"us-central1-a","network_interface":[{"access_config":[{}]}]}}},
  {"address":"google_compute_address.ip","mode":"managed","type":"google_compute_address","change":{"actions":["create"],"after":{"region":"us-central1"}}}
 ]}`

func TestQuotaDemands(t *testing.T) {
	ds, err := QuotaDemands(quotaPlanJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, d := range ds {
		got[d.Key] = d.Need
	}
	want := map[string]float64{
		"aws/ec2/L-1216C47A@eu-west-1":                  8 + 2 + 2, // m5.2xlarge, t3.micro, and m5.large to m5.xlarge; g5 is not standard
		"aws/vpc/L-F678F1CE@eu-west-1":                  1,         // the unchanged VPC is not counted
		"aws/ec2/L-0263D0A3@eu-west-1":                  1,
		"aws/elasticloadbalancing/L-53DA6B97@eu-west-1": 1, // only the application load balancer
		"azure/cores@westeurope":                        4,
		"gcp/N2_CPUS@us-central1":                       8,
		"gcp/IN_USE_ADDRESSES@us-central1":              1,
		"gcp/STATIC_ADDRESSES@us-central1":              1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: need %v, want %v", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected demands: %v", got)
	}

	res := CheckQuotas(ds, map[string]QuotaUsage{"aws/ec2/L-1216C47A@eu-west-1": {Limit: 32, Used: 24}, "aws/vpc/L-F678F1CE@eu-west-1": {Limit: 5, Used: 2}})
	status := map[string]string{}
	for _, r := range res {
		status[r.Key] = r.Status
	}
	if status["aws/ec2/L-1216C47A@eu-west-1"] != "exceeds" || status["aws/vpc/L-F678F1CE@eu-west-1"] != "ok" || status["aws/ec2/L-0263D0A3@eu-west-1"] != "unknown" {
		t.Errorf("statuses: %v", status)
	}
}

func TestInstanceSizes(t *testing.T) {
	for typ, want := range map[string]float64{"t3.micro": 2, "m5.large": 2, "c6gn.4xlarge": 16, "r7i.xlarge": 4, "a1.medium": 1} {
		if n, std := AWSInstanceVCPUs(typ); n != want || !std {
			t.Errorf("%s: %v %v", typ, n, std)
		}
	}
	if _, std := AWSInstanceVCPUs("p4d.24xlarge"); std {
		t.Error("p4d is not a standard family")
	}
	for typ, want := range map[string]float64{"e2-medium": 2, "n2-highmem-16": 16, "custom-6-23040": 6, "zones/us-central1-a/machineTypes/e2-standard-4": 4} {
		if _, n := gcpCPUs(typ); n != want {
			t.Errorf("%s: %v", typ, n)
		}
	}
	if azureVCPUs("Standard_B2ms") != 2 || azureVCPUs("Standard_E64ds_v5") != 64 {
		t.Error("azure sizes")
	}
}
