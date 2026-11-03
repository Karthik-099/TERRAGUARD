package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Offline monthly cost estimate from bundled list prices for AWS, Azure and
// Google Cloud. Fixed hourly and monthly charges are always priced; usage-based
// charges (requests, storage that grows, data transfer) are priced from a usage
// file when one is given. Prices can be overridden for negotiated rates.

// PriceBasis says what the bundled prices are; it is printed with every estimate.
const PriceBasis = "list prices, 2026-10 snapshot (USD, on-demand, 730 hours a month): AWS us-east-1, Azure East US, Google Cloud us-central1, Linux"

const hoursPerMonth = 730

// CostLine is one resource's estimated monthly charge before and after a change.
type CostLine struct {
	Address string  `json:"address"`
	Type    string  `json:"type"`
	Detail  string  `json:"detail"`
	Before  float64 `json:"before"`
	After   float64 `json:"after"`
	Usage   bool    `json:"usage,omitempty"` // includes usage-based charges from the usage file
}

// CostEstimate totals the priced resources.
type CostEstimate struct {
	Basis    string     `json:"basis"`
	Before   float64    `json:"before"`
	After    float64    `json:"after"`
	Lines    []CostLine `json:"lines"`
	Unpriced []string   `json:"unpriced,omitempty"` // resource types with no price or only usage prices and no usage given
}

// Delta is the monthly change.
func (c *CostEstimate) Delta() float64 { return c.After - c.Before }

// CostOptions carries a usage file and price overrides, both optional.
type CostOptions struct {
	// Usage is YAML: resource_usage: {address: {key: n}}, resource_type_default_usage: {type: {key: n}}.
	Usage string
	// Prices is YAML or JSON: {price key: USD}, overriding the bundled table (see Prices).
	Prices string
}

// Prices is the bundled table. Keys are stable so overrides can name them.
var Prices = map[string]float64{
	// AWS hourly
	"aws.nat_gateway.hour": 0.045, "aws.lb.hour": 0.0225, "aws.eks.hour": 0.10, "aws.ipv4.hour": 0.005,
	"aws.vpc_endpoint.az_hour": 0.01, "aws.fargate.vcpu_hour": 0.04048, "aws.fargate.gb_hour": 0.004445,
	"aws.msk.kafka.m5.large.hour": 0.21, "aws.redshift.dc2.large.hour": 0.25, "aws.redshift.ra3.xlplus.hour": 1.086,
	"aws.rds_multiplier": 1.78, "aws.cache_multiplier": 1.63, "aws.opensearch_multiplier": 1.5,
	// AWS monthly
	"aws.kms_key.month": 1, "aws.secret.month": 0.40, "aws.route53_zone.month": 0.50, "aws.rds.storage_gb": 0.115,
	"aws.ebs.gp3.gb": 0.08, "aws.ebs.gp2.gb": 0.10, "aws.ebs.io1.gb": 0.125, "aws.ebs.io2.gb": 0.125, "aws.ebs.st1.gb": 0.045,
	"aws.ebs.sc1.gb": 0.015, "aws.ebs.standard.gb": 0.05, "aws.efs.gb": 0.30, "aws.ecr.gb": 0.10, "aws.cloudwatch_alarm.month": 0.10,
	// AWS usage
	"aws.s3.gb": 0.023, "aws.s3.put_1k": 0.005, "aws.s3.get_1k": 0.0004, "aws.lambda.request_1m": 0.20, "aws.lambda.gb_second": 0.0000166667,
	"aws.dynamodb.write_1m": 0.625, "aws.dynamodb.read_1m": 0.125, "aws.dynamodb.gb": 0.25, "aws.logs.ingest_gb": 0.50, "aws.logs.store_gb": 0.03,
	"aws.nat.processed_gb": 0.045, "aws.data_out_gb": 0.09, "aws.apigw.rest_1m": 3.50, "aws.apigw.http_1m": 1.00, "aws.sqs.request_1m": 0.40,
	"aws.sns.publish_1m": 0.50, "aws.cloudfront.gb": 0.085, "aws.route53.query_1m": 0.40, "aws.lb.lcu_hour": 0.008,
	// Azure hourly
	"azure.public_ip.hour": 0.005, "azure.lb.hour": 0.025, "azure.nat_gateway.hour": 0.045, "azure.aks_standard.hour": 0.10,
	"azure.vm.d.vcpu_hour": 0.048, "azure.vm.da.vcpu_hour": 0.043, "azure.vm.e.vcpu_hour": 0.063, "azure.vm.f.vcpu_hour": 0.0423,
	"azure.vm.b.vcpu_hour": 0.0208, "azure.sql.vcore_hour": 0.2522,
	// Azure monthly
	"azure.disk.premium.gb": 0.154, "azure.disk.standardssd.gb": 0.075, "azure.disk.standard.gb": 0.046, "azure.sql.storage_gb": 0.115,
	// Azure usage
	"azure.storage.gb": 0.0184, "azure.function.execution_1m": 0.20, "azure.function.gb_second": 0.000016, "azure.data_out_gb": 0.087,
	// Google Cloud hourly
	"gcp.e2.vcpu_hour": 0.021811, "gcp.e2.gb_hour": 0.002923, "gcp.n2.vcpu_hour": 0.031611, "gcp.n2.gb_hour": 0.004237,
	"gcp.n1.vcpu_hour": 0.031611, "gcp.n1.gb_hour": 0.004237, "gcp.n2d.vcpu_hour": 0.027502, "gcp.n2d.gb_hour": 0.003686,
	"gcp.t2d.vcpu_hour": 0.027502, "gcp.t2d.gb_hour": 0.003686, "gcp.c2.vcpu_hour": 0.03398, "gcp.c2.gb_hour": 0.00455,
	"gcp.c3.vcpu_hour": 0.03465, "gcp.c3.gb_hour": 0.004642, "gcp.gke.hour": 0.10, "gcp.forwarding_rule.hour": 0.025, "gcp.ip.hour": 0.005,
	"gcp.sql.vcpu_hour": 0.0413, "gcp.sql.gb_hour": 0.007, "gcp.nat.hour": 0.044,
	// Google Cloud monthly
	"gcp.disk.pd-standard.gb": 0.04, "gcp.disk.pd-balanced.gb": 0.10, "gcp.disk.pd-ssd.gb": 0.17, "gcp.disk.pd-extreme.gb": 0.125,
	"gcp.disk.hyperdisk-balanced.gb": 0.08, "gcp.sql.storage_gb": 0.17,
	// Google Cloud usage
	"gcp.gcs.gb": 0.020, "gcp.function.invocation_1m": 0.40, "gcp.function.gb_second": 0.0000025, "gcp.data_out_gb": 0.12,
}

// Hourly prices of sizes that do not scale with vCPUs.
var fixedSizes = map[string]float64{
	"t2.nano": 0.0058, "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464, "t2.large": 0.0928, "t2.xlarge": 0.1856, "t2.2xlarge": 0.3712,
	"t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
	"t3a.nano": 0.0047, "t3a.micro": 0.0094, "t3a.small": 0.0188, "t3a.medium": 0.0376, "t3a.large": 0.0752, "t3a.xlarge": 0.1504, "t3a.2xlarge": 0.3008,
	"t4g.nano": 0.0042, "t4g.micro": 0.0084, "t4g.small": 0.0168, "t4g.medium": 0.0336, "t4g.large": 0.0672, "t4g.xlarge": 0.1344, "t4g.2xlarge": 0.2688,
	"g4dn.xlarge": 0.526, "g4dn.2xlarge": 0.752, "g5.xlarge": 1.006, "g5.2xlarge": 1.212, "g6.xlarge": 0.805, "p3.2xlarge": 3.06, "p4d.24xlarge": 32.77, "inf2.xlarge": 0.758,
	// Azure burstable and App Service plans, Google Cloud shared-core
	"Standard_B1s": 0.0104, "Standard_B1ms": 0.0207, "Standard_B2s": 0.0416, "Standard_B2ms": 0.0832, "Standard_B4ms": 0.166, "Standard_B8ms": 0.333,
	"F1": 0, "B1": 0.075, "B2": 0.15, "B3": 0.30, "S1": 0.10, "S2": 0.20, "S3": 0.40, "P1v3": 0.169, "P2v3": 0.338, "P3v3": 0.676, "P0v3": 0.084,
	"e2-micro": 0.00838, "e2-small": 0.01675, "e2-medium": 0.03351, "db-f1-micro": 0.0105, "db-g1-small": 0.035,
}

// Hourly price of the AWS .large size (2 vCPUs); other sizes scale with vCPUs.
var perLarge = map[string]float64{
	"m4": 0.10, "m5": 0.096, "m5a": 0.086, "m5n": 0.119, "m6i": 0.096, "m6a": 0.0864, "m6g": 0.077, "m7i": 0.1008, "m7a": 0.1159, "m7g": 0.0816, "m8g": 0.0898,
	"c4": 0.10, "c5": 0.085, "c5a": 0.077, "c5n": 0.108, "c6i": 0.085, "c6a": 0.0765, "c6g": 0.068, "c7i": 0.0893, "c7a": 0.1026, "c7g": 0.0725, "c8g": 0.0798,
	"r4": 0.133, "r5": 0.126, "r5a": 0.113, "r6i": 0.126, "r6a": 0.1134, "r6g": 0.1008, "r7i": 0.1323, "r7a": 0.1522, "r7g": 0.1071, "r8g": 0.1178,
	"i3": 0.156, "i4i": 0.172, "d3": 0.249, "x2gd": 0.167, "z1d": 0.186,
}

// Monthly prices of Azure SQL DTU tiers.
var azureSQLSku = map[string]float64{"Basic": 4.90, "S0": 15.03, "S1": 30.05, "S2": 75.13, "S3": 150.26, "S4": 300.52, "P1": 465.0, "P2": 930.0}

var instanceRE = regexp.MustCompile(`^([a-z0-9]+)\.(\w+)$`)

type pricer struct {
	price map[string]float64
	usage map[string]map[string]float64 // address or "type:"+type -> key -> value
}

func (p *pricer) get(k string) float64 { return p.price[k] }

// use returns a usage value for a resource; ok is false when none was given.
func (p *pricer) use(addr, typ, k string) (float64, bool) {
	if u, ok := p.usage[stripKeys(addr)][k]; ok {
		return u, true
	}
	u, ok := p.usage["type:"+typ][k]
	return u, ok
}

func newPricer(o CostOptions) (*pricer, error) {
	p := &pricer{price: map[string]float64{}, usage: map[string]map[string]float64{}}
	for k, v := range Prices {
		p.price[k] = v
	}
	if strings.TrimSpace(o.Prices) != "" {
		var over map[string]float64
		if err := yaml.Unmarshal([]byte(o.Prices), &over); err != nil {
			return nil, fmt.Errorf("prices: %w", err)
		}
		for k, v := range over {
			p.price[k] = v
		}
	}
	if strings.TrimSpace(o.Usage) != "" {
		var u struct {
			Resources map[string]map[string]float64 `yaml:"resource_usage"`
			Types     map[string]map[string]float64 `yaml:"resource_type_default_usage"`
		}
		if err := yaml.Unmarshal([]byte(o.Usage), &u); err != nil {
			return nil, fmt.Errorf("usage file: %w", err)
		}
		for a, m := range u.Resources {
			p.usage[stripKeys(a)] = m
		}
		for t, m := range u.Types {
			p.usage["type:"+t] = m
		}
	}
	return p, nil
}

var keysRE = regexp.MustCompile(`\[[^\]]*\]`)

func stripKeys(addr string) string { return keysRE.ReplaceAllString(addr, "") }

// ec2Hourly prices an EC2 instance type.
func (p *pricer) ec2Hourly(t string) (float64, bool) {
	if h, ok := fixedSizes[t]; ok {
		return h, true
	}
	m := instanceRE.FindStringSubmatch(t)
	if m == nil {
		return 0, false
	}
	base, ok := perLarge[m[1]]
	if !ok {
		return 0, false
	}
	vcpu, _ := AWSInstanceVCPUs(t)
	if vcpu == 0 {
		return 0, false
	}
	return base * vcpu / 2, true
}

var azureSizeRE2 = regexp.MustCompile(`^Standard_([A-Z]+)(\d+)[a-z]*(_v\d+)?$`)

// azureVMHourly prices an Azure VM size by series and vCPUs.
func (p *pricer) azureVMHourly(size string) (float64, bool) {
	if h, ok := fixedSizes[size]; ok {
		return h, true
	}
	m := azureSizeRE2.FindStringSubmatch(size)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.ParseFloat(m[2], 64)
	series := strings.ToLower(m[1][:1]) // D, E, F, B
	if series == "d" && strings.HasPrefix(size[len("Standard_")+len(m[1])+len(m[2]):], "a") {
		series = "da" // AMD sizes such as D4as_v5
	}
	rate, ok := p.price["azure.vm."+series+".vcpu_hour"]
	return rate * n, ok && n > 0
}

var gcpTypeRE = regexp.MustCompile(`^([a-z0-9]+)-(standard|highmem|highcpu|custom)-(\d+)(?:-(\d+))?$`)

// gcpHourly prices a Google Cloud machine type from vCPU and memory rates.
func (p *pricer) gcpHourly(t string) (float64, bool) {
	if h, ok := fixedSizes[t]; ok {
		return h, true
	}
	m := gcpTypeRE.FindStringSubmatch(t)
	if m == nil {
		return 0, false
	}
	vcpu, _ := strconv.ParseFloat(m[3], 64)
	perVCPU := map[string]float64{"standard": 4, "highmem": 8, "highcpu": 1}[m[2]]
	if m[1] == "n1" && m[2] == "standard" {
		perVCPU = 3.75
	}
	mem := vcpu * perVCPU
	if m[2] == "custom" && m[4] != "" {
		mb, _ := strconv.ParseFloat(m[4], 64)
		mem = mb / 1024
	}
	cpu, ok1 := p.price["gcp."+m[1]+".vcpu_hour"]
	gb, ok2 := p.price["gcp."+m[1]+".gb_hour"]
	return cpu*vcpu + gb*mem, ok1 && ok2
}

// priceResource returns a resource's monthly charge; usage is true when a
// usage-based charge from the usage file is included.
func (p *pricer) priceResource(addr, typ string, a map[string]any) (total float64, detail string, ok, usage bool) {
	str := func(k string) string { s, _ := get(a, k).(string); return s }
	num := func(k string, def float64) float64 {
		if f, ok := asFloat(get(a, k)); ok {
			return f
		}
		return def
	}
	u := func(k string) float64 {
		v, given := p.use(addr, typ, k)
		usage = usage || given
		return v
	}
	h := float64(hoursPerMonth)
	switch typ {
	// AWS
	case "aws_instance":
		hr, ok := p.ec2Hourly(str("instance_type"))
		return hr * h, str("instance_type"), ok, false
	case "aws_db_instance", "aws_rds_cluster_instance":
		class := strings.TrimPrefix(str("instance_class"), "db.")
		hr, ok := p.ec2Hourly(class)
		if !ok {
			return 0, str("instance_class"), false, false
		}
		hr *= p.get("aws.rds_multiplier")
		if is(a["multi_az"], true) {
			hr *= 2
		}
		gb := num("allocated_storage", 0)
		return hr*h + gb*p.get("aws.rds.storage_gb"), fmt.Sprintf("%s, %g GB", str("instance_class"), gb), true, false
	case "aws_elasticache_cluster", "aws_elasticache_replication_group":
		hr, ok := p.ec2Hourly(strings.TrimPrefix(str("node_type"), "cache."))
		n := num("num_cache_nodes", 0)
		if n == 0 {
			n = num("num_cache_clusters", 0)
		}
		if n == 0 {
			n = num("num_node_groups", 1) * (1 + num("replicas_per_node_group", 0))
		}
		return hr * p.get("aws.cache_multiplier") * n * h, fmt.Sprintf("%g x %s", n, str("node_type")), ok, false
	case "aws_opensearch_domain", "aws_elasticsearch_domain":
		t := strings.TrimSuffix(str("cluster_config.instance_type"), ".search")
		t = strings.TrimSuffix(t, ".elasticsearch")
		hr, ok := p.ec2Hourly(t)
		n := num("cluster_config.instance_count", 1)
		return hr * p.get("aws.opensearch_multiplier") * n * h, fmt.Sprintf("%g x %s", n, str("cluster_config.instance_type")), ok, false
	case "aws_msk_cluster":
		n := num("number_of_broker_nodes", 0)
		hr, ok := p.price["aws.msk."+str("broker_node_group_info.instance_type")+".hour"]
		return hr * n * h, fmt.Sprintf("%g x %s", n, str("broker_node_group_info.instance_type")), ok, false
	case "aws_redshift_cluster":
		n := num("number_of_nodes", 1)
		hr, ok := p.price["aws.redshift."+str("node_type")+".hour"]
		return hr * n * h, fmt.Sprintf("%g x %s", n, str("node_type")), ok, false
	case "aws_ebs_volume":
		t := str("type")
		if t == "" {
			t = "gp3"
		}
		per, ok := p.price["aws.ebs."+t+".gb"]
		size := num("size", 0)
		return per * size, fmt.Sprintf("%g GB %s", size, t), ok && size > 0, false
	case "aws_nat_gateway":
		gb := u("monthly_data_processed_gb")
		return p.get("aws.nat_gateway.hour")*h + gb*p.get("aws.nat.processed_gb"), "per gateway, plus data processed from usage", true, usage
	case "aws_lb", "aws_alb":
		lcu := u("lcu")
		return p.get("aws.lb.hour")*h + lcu*p.get("aws.lb.lcu_hour")*h, "base charge, plus capacity units from usage", true, usage
	case "aws_eks_cluster":
		return p.get("aws.eks.hour") * h, "control plane", true, false
	case "aws_eip":
		return p.get("aws.ipv4.hour") * h, "public IPv4 address", true, false
	case "aws_vpc_endpoint":
		if str("vpc_endpoint_type") != "Interface" {
			return 0, "gateway endpoint", true, false
		}
		azs := math.Max(1, float64(len(asStrings(a["subnet_ids"]))))
		return p.get("aws.vpc_endpoint.az_hour") * azs * h, fmt.Sprintf("interface endpoint in %g AZ(s)", azs), true, false
	case "aws_kms_key":
		return p.get("aws.kms_key.month"), "customer managed key", true, false
	case "aws_secretsmanager_secret":
		return p.get("aws.secret.month"), "per secret", true, false
	case "aws_route53_zone":
		q := u("monthly_queries")
		return p.get("aws.route53_zone.month") + q/1e6*p.get("aws.route53.query_1m"), "hosted zone", true, usage
	case "aws_cloudwatch_metric_alarm":
		return p.get("aws.cloudwatch_alarm.month"), "standard alarm", true, false
	case "aws_efs_file_system":
		return u("storage_gb") * p.get("aws.efs.gb"), "storage from usage", usage, usage
	case "aws_ecr_repository":
		return u("storage_gb") * p.get("aws.ecr.gb"), "storage from usage", usage, usage
	case "aws_s3_bucket":
		c := u("storage_gb")*p.get("aws.s3.gb") + u("monthly_put_requests")/1000*p.get("aws.s3.put_1k") + u("monthly_get_requests")/1000*p.get("aws.s3.get_1k")
		return c, "storage and requests from usage", usage, usage
	case "aws_lambda_function":
		req := u("monthly_requests")
		mem := num("memory_size", 128) / 1024
		dur := u("request_duration_ms") / 1000
		return req/1e6*p.get("aws.lambda.request_1m") + req*dur*mem*p.get("aws.lambda.gb_second"), fmt.Sprintf("%g MB, requests from usage", num("memory_size", 128)), usage, usage
	case "aws_dynamodb_table":
		if str("billing_mode") == "PROVISIONED" {
			return 0, "provisioned capacity", false, false
		}
		c := u("monthly_write_request_units")/1e6*p.get("aws.dynamodb.write_1m") + u("monthly_read_request_units")/1e6*p.get("aws.dynamodb.read_1m") + u("storage_gb")*p.get("aws.dynamodb.gb")
		return c, "on-demand, requests from usage", usage, usage
	case "aws_cloudwatch_log_group":
		return u("monthly_data_ingested_gb")*p.get("aws.logs.ingest_gb") + u("storage_gb")*p.get("aws.logs.store_gb"), "ingestion from usage", usage, usage
	case "aws_sqs_queue":
		return u("monthly_requests") / 1e6 * p.get("aws.sqs.request_1m"), "requests from usage", usage, usage
	case "aws_sns_topic":
		return u("monthly_requests") / 1e6 * p.get("aws.sns.publish_1m"), "publishes from usage", usage, usage
	case "aws_api_gateway_rest_api":
		return u("monthly_requests") / 1e6 * p.get("aws.apigw.rest_1m"), "requests from usage", usage, usage
	case "aws_apigatewayv2_api":
		return u("monthly_requests") / 1e6 * p.get("aws.apigw.http_1m"), "requests from usage", usage, usage
	case "aws_cloudfront_distribution":
		return u("monthly_data_transfer_gb") * p.get("aws.cloudfront.gb"), "transfer from usage", usage, usage

	// Azure
	case "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine":
		size := str("size")
		if size == "" {
			size = str("vm_size")
		}
		hr, ok := p.azureVMHourly(size)
		return hr * h, size, ok, false
	case "azurerm_linux_virtual_machine_scale_set", "azurerm_windows_virtual_machine_scale_set":
		hr, ok := p.azureVMHourly(str("sku"))
		n := num("instances", 1)
		return hr * n * h, fmt.Sprintf("%g x %s", n, str("sku")), ok, false
	case "azurerm_kubernetes_cluster":
		hr, ok := p.azureVMHourly(str("default_node_pool.vm_size"))
		n := num("default_node_pool.node_count", 1)
		plane := 0.0
		if str("sku_tier") == "Standard" || str("sku_tier") == "Premium" {
			plane = p.get("azure.aks_standard.hour")
		}
		return (hr*n + plane) * h, fmt.Sprintf("%g x %s", n, str("default_node_pool.vm_size")), ok, false
	case "azurerm_kubernetes_cluster_node_pool":
		hr, ok := p.azureVMHourly(str("vm_size"))
		n := num("node_count", 1)
		return hr * n * h, fmt.Sprintf("%g x %s", n, str("vm_size")), ok, false
	case "azurerm_managed_disk":
		t := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(str("storage_account_type"), "_LRS"), "_ZRS"))
		key := map[string]string{"premium": "premium", "standardssd": "standardssd", "standard": "standard", "premiumv2": "premium"}[t]
		size := num("disk_size_gb", 0)
		per, ok := p.price["azure.disk."+key+".gb"]
		return per * size, fmt.Sprintf("%g GB %s", size, str("storage_account_type")), ok && size > 0, false
	case "azurerm_public_ip":
		return p.get("azure.public_ip.hour") * h, "public IP address", true, false
	case "azurerm_lb":
		if strings.EqualFold(str("sku"), "Basic") {
			return 0, "basic load balancer", true, false
		}
		return p.get("azure.lb.hour") * h, "standard load balancer", true, false
	case "azurerm_nat_gateway":
		return p.get("azure.nat_gateway.hour") * h, "per gateway", true, false
	case "azurerm_service_plan", "azurerm_app_service_plan":
		sku := str("sku_name")
		if sku == "" {
			sku = str("sku.size")
		}
		hr, ok := fixedSizes[sku]
		n := num("worker_count", 1)
		return hr * n * h, fmt.Sprintf("%g x %s", n, sku), ok, false
	case "azurerm_mssql_database":
		sku := str("sku_name")
		if m, ok := azureSQLSku[sku]; ok {
			return m, sku, true, false
		}
		if mm := regexp.MustCompile(`^GP_Gen5_(\d+)$`).FindStringSubmatch(sku); mm != nil {
			n, _ := strconv.ParseFloat(mm[1], 64)
			return n*p.get("azure.sql.vcore_hour")*h + num("max_size_gb", 0)*p.get("azure.sql.storage_gb"), sku, true, false
		}
		return 0, sku, false, false
	case "azurerm_storage_account":
		return u("storage_gb") * p.get("azure.storage.gb"), "storage from usage", usage, usage
	case "azurerm_linux_function_app", "azurerm_windows_function_app", "azurerm_function_app":
		req := u("monthly_executions")
		gbs := req * u("execution_duration_ms") / 1000 * u("memory_mb") / 1024
		return req/1e6*p.get("azure.function.execution_1m") + gbs*p.get("azure.function.gb_second"), "consumption, executions from usage", usage, usage

	// Google Cloud
	case "google_compute_instance":
		hr, ok := p.gcpHourly(path0(str("machine_type")))
		return hr * h, str("machine_type"), ok, false
	case "google_compute_disk":
		t := str("type")
		if t == "" {
			t = "pd-standard"
		}
		per, ok := p.price["gcp.disk."+path0(t)+".gb"]
		size := num("size", 0)
		return per * size, fmt.Sprintf("%g GB %s", size, t), ok && size > 0, false
	case "google_container_cluster":
		return p.get("gcp.gke.hour") * h, "cluster management fee", true, false
	case "google_container_node_pool":
		hr, ok := p.gcpHourly(str("node_config.machine_type"))
		n := num("node_count", num("initial_node_count", 1))
		return hr * n * h, fmt.Sprintf("%g x %s per zone", n, str("node_config.machine_type")), ok, false
	case "google_sql_database_instance":
		tier := str("settings.tier")
		if hr, ok := fixedSizes[tier]; ok {
			return hr * h, tier, true, false
		}
		if mm := regexp.MustCompile(`^db-custom-(\d+)-(\d+)$`).FindStringSubmatch(tier); mm != nil {
			cpu, _ := strconv.ParseFloat(mm[1], 64)
			mb, _ := strconv.ParseFloat(mm[2], 64)
			hr := cpu*p.get("gcp.sql.vcpu_hour") + mb/1024*p.get("gcp.sql.gb_hour")
			if str("settings.availability_type") == "REGIONAL" {
				hr *= 2
			}
			return hr*h + num("settings.disk_size", 10)*p.get("gcp.sql.storage_gb"), tier, true, false
		}
		return 0, tier, false, false
	case "google_compute_forwarding_rule", "google_compute_global_forwarding_rule":
		return p.get("gcp.forwarding_rule.hour") * h, "forwarding rule", true, false
	case "google_compute_address", "google_compute_global_address":
		return p.get("gcp.ip.hour") * h, "static IP address", true, false
	case "google_compute_router_nat":
		return p.get("gcp.nat.hour") * h, "NAT gateway", true, false
	case "google_storage_bucket":
		return u("storage_gb") * p.get("gcp.gcs.gb"), "storage from usage", usage, usage
	case "google_cloudfunctions_function", "google_cloudfunctions2_function":
		req := u("monthly_invocations")
		gbs := req * u("execution_duration_ms") / 1000 * num("available_memory_mb", 256) / 1024
		return req/1e6*p.get("gcp.function.invocation_1m") + gbs*p.get("gcp.function.gb_second"), "invocations from usage", usage, usage
	}
	return 0, "", false, false
}

// path0 keeps the last segment of a self link such as zones/x/machineTypes/e2-small.
func path0(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func pricedCloud(t string) bool {
	return strings.HasPrefix(t, "aws_") || strings.HasPrefix(t, "azurerm_") || strings.HasPrefix(t, "google_")
}

// EstimateCost prices a plan's resources before and after it applies.
func EstimateCost(planJSON string) (*CostEstimate, error) {
	return EstimateCostWith(planJSON, CostOptions{})
}

// EstimateCostWith is EstimateCost with a usage file and price overrides.
func EstimateCostWith(planJSON string, o CostOptions) (*CostEstimate, error) {
	p, err := newPricer(o)
	if err != nil {
		return nil, err
	}
	var plan quotaPlan
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		return nil, fmt.Errorf("plan is not valid JSON: %w", err)
	}
	est := newEstimate()
	unpriced := map[string]bool{}
	for _, rc := range plan.ResourceChanges {
		if rc.Mode == "data" || !pricedCloud(rc.Type) {
			continue
		}
		line := CostLine{Address: rc.Address, Type: rc.Type}
		priced := false
		if rc.Change.Before != nil {
			if v, d, ok, u := p.priceResource(rc.Address, rc.Type, rc.Change.Before); ok {
				line.Before, line.Detail, line.Usage, priced = v, d, u, true
			}
		}
		deleted := len(rc.Change.Actions) == 1 && rc.Change.Actions[0] == "delete"
		if rc.Change.After != nil && !deleted {
			if v, d, ok, u := p.priceResource(rc.Address, rc.Type, rc.Change.After); ok {
				line.After, line.Detail, line.Usage, priced = v, d, line.Usage || u, true
			}
		}
		est.add(line, priced, unpriced)
	}
	return est.done(unpriced), nil
}

// EstimateCostFromCode prices the resources in Terraform code, for a module
// that has no plan yet. Values that come from unresolved expressions are not
// priced, and count and for_each are counted once.
func EstimateCostFromCode(files map[string]string, o CostOptions) (*CostEstimate, error) {
	p, err := newPricer(o)
	if err != nil {
		return nil, err
	}
	m := Parse(files)
	est := newEstimate()
	unpriced := map[string]bool{}
	for _, r := range m.Resources {
		if r.Mode == "data" || r.Format != "" || !pricedCloud(r.Type) {
			continue
		}
		v, d, ok, u := p.priceResource(r.Address, r.Type, r.Attrs)
		est.add(CostLine{Address: r.Address, Type: r.Type, Detail: d, After: v, Usage: u}, ok, unpriced)
	}
	return est.done(unpriced), nil
}

func newEstimate() *CostEstimate { return &CostEstimate{Basis: PriceBasis, Lines: []CostLine{}} }

func (c *CostEstimate) add(l CostLine, priced bool, unpriced map[string]bool) {
	if !priced {
		if !freeType(l.Type) {
			unpriced[l.Type] = true
		}
		return
	}
	if l.Before == 0 && l.After == 0 {
		return
	}
	l.Before, l.After = round2(l.Before), round2(l.After)
	c.Before += l.Before
	c.After += l.After
	c.Lines = append(c.Lines, l)
}

func (c *CostEstimate) done(unpriced map[string]bool) *CostEstimate {
	sort.Slice(c.Lines, func(i, j int) bool {
		return math.Abs(c.Lines[i].After-c.Lines[i].Before) > math.Abs(c.Lines[j].After-c.Lines[j].Before)
	})
	c.Before, c.After = round2(c.Before), round2(c.After)
	c.Unpriced = sortedKeys(unpriced)
	return c
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// CostMarkdown renders an estimate for a pull request comment.
func CostMarkdown(c *CostEstimate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Estimated monthly cost\n\n%s a month to %s (%s).\n\n", money(c.Before), money(c.After), signed(c.Delta()))
	if len(c.Lines) > 0 {
		b.WriteString("| Resource | Detail | Before | After |\n|---|---|---:|---:|\n")
		for _, l := range c.Lines {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", l.Address, l.Detail, money(l.Before), money(l.After))
		}
	}
	fmt.Fprintf(&b, "\nBasis: %s. Usage-based charges are included only where a usage file gives them", c.Basis)
	if len(c.Unpriced) > 0 {
		fmt.Fprintf(&b, "; not priced: %s", strings.Join(c.Unpriced, ", "))
	}
	b.WriteString(".\n")
	return b.String()
}

func money(f float64) string { return "$" + strconv.FormatFloat(f, 'f', 2, 64) }

func signed(f float64) string {
	if f >= 0 {
		return "+" + money(f)
	}
	return "-" + money(-f)
}

var freeExact = map[string]bool{
	"aws_vpc": true, "aws_subnet": true, "aws_security_group": true, "aws_route_table": true, "aws_route": true, "aws_internet_gateway": true,
	"aws_default_security_group": true, "aws_cloudtrail": true, "aws_lambda_function_url": true, "aws_lambda_permission": true, "aws_key_pair": true,
	"aws_launch_template": true, "aws_db_subnet_group": true, "aws_db_parameter_group": true, "aws_elasticache_subnet_group": true, "aws_lb_listener": true,
	"aws_lb_target_group": true, "aws_ecs_cluster": true, "aws_ecs_task_definition": true, "aws_cloudwatch_event_rule": true, "aws_sns_topic_subscription": true,
	"azurerm_resource_group": true, "azurerm_virtual_network": true, "azurerm_subnet": true, "azurerm_network_security_group": true,
	"azurerm_network_interface": true, "azurerm_user_assigned_identity": true, "azurerm_log_analytics_workspace": false,
	"google_compute_network": true, "google_compute_subnetwork": true, "google_compute_firewall": true, "google_project_service": true,
	"google_service_account": true, "google_compute_router": true,
}

var freeRE = regexp.MustCompile(`^(aws_iam_|azurerm_role_|google_.*_iam_)|_(policy|policy_attachment|attachment|association|rule|acl|versioning|public_access_block|ownership_controls|server_side_encryption_configuration|lifecycle_configuration|logging|notification|tag|tags|alias|key_rotation)$`)

// freeType is true for configuration resources that have no charge of their own.
func freeType(t string) bool { return freeExact[t] || freeRE.MatchString(t) }
