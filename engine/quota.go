package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Quotas are only enforced by the cloud at create time, so no plan or static
// check sees them. QuotaDemands counts what a plan will add against each common
// quota; the CLI compares that with live limits (terraguard preflight).

// QuotaDemand is what a plan needs from one quota in one region.
type QuotaDemand struct {
	Key       string   `json:"key"` // e.g. aws/ec2/L-1216C47A@eu-west-1
	Cloud     string   `json:"cloud"`
	Region    string   `json:"region"`
	Quota     string   `json:"quota"` // service code and quota code, or metric
	Title     string   `json:"title"`
	Need      float64  `json:"need"`
	Resources []string `json:"resources"`
	Estimated bool     `json:"estimated,omitempty"` // a size was inferred from a type name
}

// QuotaUsage is a quota's limit and current usage.
type QuotaUsage struct {
	Limit float64 `json:"limit"`
	Used  float64 `json:"used"`
}

// QuotaResult is one demand checked against live usage.
type QuotaResult struct {
	QuotaDemand
	Limit  float64 `json:"limit,omitempty"`
	Used   float64 `json:"used,omitempty"`
	Free   float64 `json:"free,omitempty"`
	Status string  `json:"status"` // ok, exceeds, unknown
}

type quotaPlan struct {
	FormatVersion string `json:"format_version"`
	Configuration struct {
		ProviderConfig map[string]struct {
			Name        string `json:"name"`
			Expressions map[string]struct {
				ConstantValue any `json:"constant_value"`
			} `json:"expressions"`
		} `json:"provider_config"`
		RootModule configModule `json:"root_module"`
	} `json:"configuration"`
	ResourceChanges []struct {
		Address string `json:"address"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Change  struct {
			Actions []string       `json:"actions"`
			Before  map[string]any `json:"before"`
			After   map[string]any `json:"after"`
		} `json:"change"`
	} `json:"resource_changes"`
}

type configModule struct {
	Resources []struct {
		Address           string `json:"address"`
		ProviderConfigKey string `json:"provider_config_key"`
	} `json:"resources"`
	ModuleCalls map[string]struct {
		Module configModule `json:"module"`
	} `json:"module_calls"`
}

// providerKeys maps configuration addresses (module.x.aws_vpc.v) to the
// provider configuration they use, so aliased providers keep their region.
func (m configModule) providerKeys(prefix string, out map[string]string) {
	for _, r := range m.Resources {
		out[prefix+r.Address] = r.ProviderConfigKey
	}
	for name, mc := range m.ModuleCalls {
		mc.Module.providerKeys(prefix+"module."+name+".", out)
	}
}

var instanceKeyRE = regexp.MustCompile(`\[[^\]]*\]`)

// awsCounted maps resource types to the quota each one uses, one per resource.
var awsCounted = map[string][3]string{ // type -> service, quota code, title
	"aws_vpc":                  {"vpc", "L-F678F1CE", "VPCs per Region"},
	"aws_eip":                  {"ec2", "L-0263D0A3", "EC2-VPC Elastic IPs"},
	"aws_internet_gateway":     {"vpc", "L-A4707A72", "Internet gateways per Region"},
	"aws_db_instance":          {"rds", "L-7B6409FD", "DB instances"},
	"aws_s3_bucket":            {"s3", "L-DC2B2D3D", "General purpose buckets"},
	"aws_rds_cluster_instance": {"rds", "L-7B6409FD", "DB instances"},
}

const awsVCPUQuota = "L-1216C47A" // Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances

// QuotaDemands reads `terraform show -json` output. defaultRegion is used when
// the provider's region is not a literal (variables, environment).
func QuotaDemands(planJSON, defaultRegion string) ([]QuotaDemand, error) {
	var p quotaPlan
	if err := json.Unmarshal([]byte(planJSON), &p); err != nil {
		return nil, fmt.Errorf("plan is not valid JSON: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, fmt.Errorf("not a Terraform JSON plan; produce one with: terraform show -json tfplan > plan.json")
	}
	regionOf := func(key string) string {
		if pc, ok := p.Configuration.ProviderConfig[key]; ok {
			if r, ok := pc.Expressions["region"].ConstantValue.(string); ok && r != "" {
				return r
			}
		}
		return ""
	}
	keys := map[string]string{}
	p.Configuration.RootModule.providerKeys("", keys)
	awsRegionFor := func(addr string) string {
		key := keys[instanceKeyRE.ReplaceAllString(addr, "")]
		if key == "" {
			key = "aws"
		}
		if r := regionOf(key); r != "" {
			return r
		}
		if r := regionOf(key[strings.LastIndex(key, ":")+1:]); r != "" { // module-scoped keys like "edge:aws"
			return r
		}
		if r := regionOf("aws"); r != "" {
			return r
		}
		return defaultRegion
	}
	demands := map[string]*QuotaDemand{}
	add := func(cloud, region, quota, title, addr string, n float64, estimated bool) {
		if n <= 0 {
			return
		}
		if region == "" {
			region = "unknown"
		}
		key := cloud + "/" + quota + "@" + region
		d := demands[key]
		if d == nil {
			d = &QuotaDemand{Key: key, Cloud: cloud, Region: region, Quota: quota, Title: title}
			demands[key] = d
		}
		d.Need += n
		d.Resources = append(d.Resources, addr)
		d.Estimated = d.Estimated || estimated
	}
	for _, rc := range p.ResourceChanges {
		if rc.Mode == "data" {
			continue
		}
		// create_before_destroy replacements briefly need room for both copies.
		create := len(rc.Change.Actions) >= 1 && rc.Change.Actions[0] == "create"
		update := len(rc.Change.Actions) == 1 && rc.Change.Actions[0] == "update"
		after, before := rc.Change.After, rc.Change.Before
		str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
		switch {
		case strings.HasPrefix(rc.Type, "aws_"):
			awsRegion := awsRegionFor(rc.Address)
			if q, ok := awsCounted[rc.Type]; ok && create {
				add("aws", awsRegion, q[0]+"/"+q[1], q[2], rc.Address, 1, false)
			}
			if rc.Type == "aws_lb" && create && (str(after, "load_balancer_type") == "" || str(after, "load_balancer_type") == "application") {
				add("aws", awsRegion, "elasticloadbalancing/L-53DA6B97", "Application Load Balancers per Region", rc.Address, 1, false)
			}
			if rc.Type == "aws_instance" && (create || update) {
				n, std := AWSInstanceVCPUs(str(after, "instance_type"))
				if update {
					was, _ := AWSInstanceVCPUs(str(before, "instance_type"))
					n -= was
				}
				if std {
					add("aws", awsRegion, "ec2/"+awsVCPUQuota, "Running On-Demand Standard instances (vCPUs)", rc.Address, n, true)
				}
			}
		case strings.HasPrefix(rc.Type, "azurerm_"):
			loc := strings.ToLower(strings.ReplaceAll(str(after, "location"), " ", ""))
			if strings.Contains(rc.Type, "virtual_machine") && (create || update) {
				size := str(after, "size")
				if size == "" {
					size = str(after, "sku")
				}
				n := azureVCPUs(size)
				if strings.HasSuffix(rc.Type, "_scale_set") {
					if inst, ok := asFloat(after["instances"]); ok {
						n *= inst
					}
				}
				if update {
					n -= azureVCPUs(str(before, "size"))
				}
				add("azure", loc, "cores", "Total regional vCPUs", rc.Address, n, true)
			}
			if rc.Type == "azurerm_public_ip" && create {
				add("azure", loc, "PublicIPAddresses", "Public IP addresses", rc.Address, 1, false)
			}
		case strings.HasPrefix(rc.Type, "google_"):
			region := str(after, "region")
			if zone := str(after, "zone"); region == "" && zone != "" {
				region = zone[:max(0, strings.LastIndex(zone, "-"))]
			}
			if rc.Type == "google_compute_instance" && (create || update) {
				metric, n := gcpCPUs(str(after, "machine_type"))
				if update {
					_, was := gcpCPUs(str(before, "machine_type"))
					n -= was
				}
				add("gcp", region, metric, metric+" (vCPUs)", rc.Address, n, true)
				if create {
					if nis, ok := after["network_interface"].([]any); ok {
						for _, ni := range nis {
							if m, ok := ni.(map[string]any); ok && len(asList(m["access_config"])) > 0 {
								add("gcp", region, "IN_USE_ADDRESSES", "In-use external IP addresses", rc.Address, 1, false)
							}
						}
					}
				}
			}
			if rc.Type == "google_compute_address" && create && !strings.EqualFold(str(after, "address_type"), "INTERNAL") {
				add("gcp", region, "STATIC_ADDRESSES", "Static external IP addresses", rc.Address, 1, false)
			}
		}
	}
	out := make([]QuotaDemand, 0, len(demands))
	for _, d := range demands {
		sort.Strings(d.Resources)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// CheckQuotas compares demands with usage keyed by QuotaDemand.Key. headroom
// is the percentage of each limit to keep spare, because another pipeline can
// use quota between preflight and apply; a plan that only fits by eating into
// it is reported as "tight".
func CheckQuotas(demands []QuotaDemand, usage map[string]QuotaUsage, headroom float64) []QuotaResult {
	out := make([]QuotaResult, 0, len(demands))
	for _, d := range demands {
		r := QuotaResult{QuotaDemand: d, Status: "unknown"}
		if u, ok := usage[d.Key]; ok {
			r.Limit, r.Used, r.Free = u.Limit, u.Used, u.Limit-u.Used
			switch {
			case d.Need > r.Free:
				r.Status = "exceeds"
			case d.Need > r.Free-u.Limit*headroom/100:
				r.Status = "tight"
			default:
				r.Status = "ok"
			}
		}
		out = append(out, r)
	}
	return out
}

func asList(v any) []any { l, _ := v.([]any); return l }

var (
	awsTypeRE   = regexp.MustCompile(`^([a-z]+)(\d*)([a-z-]*)\.(\d*)(nano|micro|small|medium|large|xlarge|metal[a-z0-9-]*)$`)
	azureSizeRE = regexp.MustCompile(`(?i)^Standard_[A-Z]+(\d+)`)
	gcpCustomRE = regexp.MustCompile(`custom-(\d+)-`)
	gcpSizeRE   = regexp.MustCompile(`-(\d+)$`)
)

// AWSInstanceVCPUs estimates vCPUs from an instance type and whether it counts toward
// the standard on-demand quota (families A, C, D, H, I, M, R, T, Z).
func AWSInstanceVCPUs(t string) (float64, bool) {
	m := awsTypeRE.FindStringSubmatch(t)
	if m == nil {
		return 0, false
	}
	std := strings.ContainsAny(m[1][:1], "acdhimrtz") && !strings.HasPrefix(m[1], "inf")
	n, _ := strconv.ParseFloat(m[4], 64)
	switch size := m[5]; {
	case size == "xlarge" && n > 0:
		return 4 * n, std
	case size == "xlarge":
		return 4, std
	case size == "large":
		return 2, std
	case size == "medium" && m[1] == "a":
		return 1, std
	case size == "nano" || size == "micro" || size == "small" || size == "medium":
		return 2, std
	}
	return 0, std // metal sizes vary by family; not estimated
}

func azureVCPUs(size string) float64 {
	if m := azureSizeRE.FindStringSubmatch(size); m != nil {
		n, _ := strconv.ParseFloat(m[1], 64)
		return n
	}
	return 0
}

// gcpCPUs returns the regional quota metric and vCPUs for a machine type.
func gcpCPUs(t string) (string, float64) {
	t = t[strings.LastIndex(t, "/")+1:]
	family := strings.SplitN(t, "-", 2)[0]
	metric := "CPUS"
	switch family {
	case "n2", "n2d", "c2", "c2d", "c3", "c3d", "c4", "m1", "m2", "m3", "a2", "a3", "t2d", "t2a", "n4", "h3", "z3":
		metric = strings.ToUpper(family) + "_CPUS"
	}
	if m := gcpCustomRE.FindStringSubmatch(t); m != nil {
		n, _ := strconv.ParseFloat(m[1], 64)
		return metric, n
	}
	if m := gcpSizeRE.FindStringSubmatch(t); m != nil {
		n, _ := strconv.ParseFloat(m[1], 64)
		return metric, n
	}
	switch t {
	case "f1-micro", "g1-small":
		return metric, 1
	case "e2-micro", "e2-small", "e2-medium":
		return metric, 2
	}
	return metric, 0
}

// BucketName is an S3 bucket the plan creates with a known name. Names are
// global across all AWS accounts, so a taken name fails at apply, not plan.
type BucketName struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	Status  string `json:"status"` // free, taken, exists, unknown
}

// NewBucketNames lists S3 buckets the plan creates with a literal name.
func NewBucketNames(planJSON string) []BucketName {
	var p quotaPlan
	if json.Unmarshal([]byte(planJSON), &p) != nil {
		return nil
	}
	var out []BucketName
	for _, rc := range p.ResourceChanges {
		if rc.Type != "aws_s3_bucket" || rc.Mode == "data" || len(rc.Change.Actions) != 1 || rc.Change.Actions[0] != "create" {
			continue
		}
		if name, ok := rc.Change.After["bucket"].(string); ok && name != "" {
			out = append(out, BucketName{Address: rc.Address, Name: name, Status: "unknown"})
		}
	}
	return out
}
