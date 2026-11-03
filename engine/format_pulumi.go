package engine

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Pulumi YAML programs. The classic aws, azure and gcp providers are generated
// from the Terraform providers, so a resource's properties are the Terraform
// arguments in camelCase. They are converted back to the Terraform type and
// snake_case attributes (nested objects as blocks, guided by the bundled
// provider schemas), so the Terraform rules run on them unchanged. Crossplane's
// Upjet providers use the same conversion (format_crossplane.go).

const FormatPulumi = "pulumi"

func init() { formatParsers[FormatPulumi] = parsePulumi }

// isPulumiFile reports a Pulumi YAML program: Pulumi.yaml (or a stack file) with resources.
func isPulumiFile(lower, src string) bool {
	if !(strings.HasPrefix(lower, "pulumi.") && (strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"))) {
		return false
	}
	return topResources.MatchString(src)
}

var topResources = regexp.MustCompile(`(?m)^resources:`)

// tfProviderPrefix maps a Pulumi package or Crossplane provider to the Terraform type prefix.
var tfProviderPrefix = map[string]string{"aws": "aws", "azure": "azurerm", "gcp": "google"}

// tfModuleAliases are modules (Pulumi) or API groups (Crossplane) whose
// Terraform type prefix differs from the module name.
var tfModuleAliases = map[string]string{
	"aws:rds": "db", "aws:apigateway": "api_gateway", "aws:directoryservice": "directory_service",
	"aws:ec2transitgateway": "ec2_transit_gateway", "aws:cfg": "config", "aws:alb": "lb", "aws:elbv2": "lb",
	"aws:elasticloadbalancingv2": "lb", "aws:elasticloadbalancing": "elb",
	"azure:monitoring": "monitor", "azure:keyvault": "key_vault", "azure:appservice": "app_service",
	"gcp:projects": "project", "gcp:organizations": "organization", "gcp:serviceaccount": "service_account",
	"gcp:cloudrun": "cloud_run", "gcp:cloudrunv2": "cloud_run_v2",
}

// tfTypeExceptions are tokens (provider:module:Resource) the naming rules cannot derive.
var tfTypeExceptions = map[string]string{
	"aws:alb:LoadBalancer": "aws_lb", "aws:lb:LoadBalancer": "aws_lb", "aws:elb:LoadBalancer": "aws_elb",
	"aws:cloudtrail:Trail": "aws_cloudtrail", "aws:ec2transitgateway:TransitGateway": "aws_ec2_transit_gateway",
	"aws:cfg:Recorder": "aws_config_configuration_recorder", "aws:cfg:Rule": "aws_config_config_rule",
	"aws:s3:BucketV2": "aws_s3_bucket", "aws:s3:BucketAclV2": "aws_s3_bucket_acl",
	"aws:s3:BucketVersioningV2": "aws_s3_bucket_versioning", "aws:s3:BucketLoggingV2": "aws_s3_bucket_logging",
	"aws:s3:BucketServerSideEncryptionConfigurationV2": "aws_s3_bucket_server_side_encryption_configuration",
	"aws:s3:BucketLifecycleConfigurationV2":            "aws_s3_bucket_lifecycle_configuration",
	"aws:s3:BucketWebsiteConfigurationV2":              "aws_s3_bucket_website_configuration",
	"aws:s3:BucketCorsConfigurationV2":                 "aws_s3_bucket_cors_configuration",
	"aws:s3:BucketObjectv2":                            "aws_s3_object", "aws:s3:BucketObject": "aws_s3_object",
	"aws:ec2:SecurityGroupRule": "aws_security_group_rule", "aws:ec2:SecurityGroupIngressRule": "aws_vpc_security_group_ingress_rule",
	"aws:ec2:SecurityGroupEgressRule": "aws_vpc_security_group_egress_rule",
	"azure:keyvault:Vault":            "azurerm_key_vault", "azure:core:ResourceGroup": "azurerm_resource_group",
	"gcp:serviceaccount:Account": "google_service_account", "gcp:cloudplatform:ServiceAccount": "google_service_account",
}

// tfTypes is the set of resource types in the bundled schemas.
var tfTypes = sync.OnceValue(func() map[string]*schemaBlock {
	out := map[string]*schemaBlock{}
	if b := bundled(); b != nil {
		for _, p := range b.Providers {
			for t, e := range p.Resources {
				out[t] = &e.Block
			}
		}
	}
	return out
})

// tfResourceType maps a provider, module and resource name (CamelCase) to a
// Terraform resource type, or "" when no known type matches.
func tfResourceType(provider, module, resource string) string {
	if t, ok := tfTypeExceptions[provider+":"+module+":"+resource]; ok {
		return t
	}
	prefix, ok := tfProviderPrefix[provider]
	if !ok {
		return ""
	}
	known, r := tfTypes(), k8sSnake(resource)
	var cands []string
	if module != "" {
		cands = append(cands, prefix+"_"+strings.ToLower(module)+"_"+r)
		if a := tfModuleAliases[provider+":"+module]; a != "" {
			cands = append(cands, prefix+"_"+a+"_"+r)
		}
	}
	cands = append(cands, prefix+"_"+r)
	for _, c := range cands {
		if _, ok := known[c]; ok {
			return c
		}
	}
	return ""
}

// tfName finds the schema name for a camelCase key, undoing the plural that
// Pulumi gives list blocks (networkInterfaces -> network_interface).
func tfName(k string, sb *schemaBlock) (name string, attr *schemaAttr, bt *schemaBlockType) {
	s := k8sSnake(k)
	if sb == nil {
		return s, nil, nil
	}
	cands := []string{s}
	if strings.HasSuffix(s, "ies") {
		cands = append(cands, strings.TrimSuffix(s, "ies")+"y")
	}
	if strings.HasSuffix(s, "s") {
		cands = append(cands, strings.TrimSuffix(s, "s"), strings.TrimSuffix(s, "es"))
	}
	for _, c := range cands {
		if a, ok := sb.Attributes[c]; ok {
			return c, &a, nil
		}
		if b, ok := sb.BlockTypes[c]; ok {
			return c, nil, &b
		}
	}
	return s, nil, nil
}

// tfConv converts camelCase properties into Terraform's shape: snake_case
// names, blocks as lists of objects, map attributes (tags) left as they are.
// src and dst are the source and Terraform paths, for line numbers.
func tfConv(m map[string]any, sb *schemaBlock, src, dst string, lines, out map[string]int) map[string]any {
	res := map[string]any{}
	for _, k := range sortedKeys(m) {
		v, sp := m[k], join(src, k)
		nk, attr, bt := tfName(k, sb)
		dp := join(dst, nk)
		k8sRecord(out, dp, lines[sp])
		var inner *schemaBlock
		if bt != nil {
			inner = &bt.Block
		}
		block := bt != nil || attr != nil && attr.takesBlocks()
		if attr == nil && bt == nil { // not in the schema: objects read as blocks, as HCL writes them
			switch t := v.(type) {
			case map[string]any:
				block = true
			case []any:
				block = len(t) > 0
				for _, e := range t {
					if _, ok := e.(map[string]any); !ok {
						block = false
					}
				}
			}
		}
		if !block {
			if mv, ok := v.(map[string]any); ok {
				for mk := range mv {
					k8sRecord(out, dp+"."+mk, lines[sp+"."+mk])
				}
			}
			res[nk] = v
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			k8sRecord(out, dp+".0", lines[sp])
			res[nk] = []any{tfConv(t, inner, sp, dp+".0", lines, out)}
		case []any:
			l := make([]any, len(t))
			for i, e := range t {
				ip, dip := sp+"."+strconv.Itoa(i), dp+"."+strconv.Itoa(i)
				k8sRecord(out, dip, lines[ip])
				if em, ok := e.(map[string]any); ok {
					l[i] = tfConv(em, inner, ip, dip, lines, out)
				} else {
					l[i] = e
				}
			}
			res[nk] = l
		default:
			res[nk] = v
		}
	}
	return res
}

// pulumiInterp matches ${resource.property} and ${resource}.
var pulumiInterp = regexp.MustCompile(`\$\{([A-Za-z0-9_-]+)`)

// pulumiValues turns interpolations and fn:: calls into Unknown, calling ref
// for each resource name they mention.
func pulumiValues(v any, ref func(string)) any {
	switch t := v.(type) {
	case string:
		if strings.Contains(t, "${") {
			for _, m := range pulumiInterp.FindAllStringSubmatch(t, -1) {
				ref(m[1])
			}
			return Unknown{Expr: t}
		}
	case map[string]any:
		if len(t) == 1 {
			for k, x := range t {
				if strings.HasPrefix(strings.ToLower(k), "fn::") {
					pulumiValues(x, ref)
					b, _ := json.Marshal(cfnPlain(x))
					return Unknown{Expr: k + " " + string(b)}
				}
			}
		}
		for k, x := range t {
			t[k] = pulumiValues(x, ref)
		}
	case []any:
		for i, x := range t {
			t[i] = pulumiValues(x, ref)
		}
	}
	return v
}

// pulumiToken splits "aws:s3/bucket:Bucket" or "aws:s3:Bucket" into package, module and resource.
func pulumiToken(tok string) (pkg, module, resource string, ok bool) {
	parts := strings.Split(tok, ":")
	if len(parts) != 3 {
		return "", "", "", false
	}
	module, _, _ = strings.Cut(parts[1], "/")
	return parts[0], module, parts[2], true
}

func parsePulumi(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	var syntax []Finding
	if err != nil {
		syntax = append(syntax, formatSyntax(name, "Pulumi YAML", err))
	}
	var out []*Resource
	for di, d := range docs {
		root, _ := d.value.(map[string]any)
		res, _ := root["resources"].(map[string]any)
		addr := map[string]string{} // logical name -> address, for references
		refs := map[*Resource][]string{}
		for _, id := range sortedKeys(res) {
			obj, _ := res[id].(map[string]any)
			tok, _ := obj["type"].(string)
			if obj == nil || tok == "" || obj["get"] != nil { // get: reads an existing resource
				continue
			}
			var named []string
			props, _ := pulumiValues(obj["properties"], func(n string) { named = append(named, n) }).(map[string]any)
			if props == nil {
				props = map[string]any{}
			}
			base := "resources." + id
			pl := subLines(d.lines, base+".properties")
			pkg, module, resource, _ := pulumiToken(tok)
			var rs []*Resource
			if pkg == "kubernetes" { // the properties are the manifest
				meta, _ := props["metadata"].(map[string]any)
				if meta == nil {
					meta = map[string]any{}
					props["metadata"] = meta
				}
				if meta["name"] == nil {
					meta["name"] = id
				}
				props["kind"] = resource
				rs = k8sObjects(name, props, pl, di, base+".properties")
			} else {
				r := &Resource{Mode: "managed", Type: tok, Name: id, File: name, Line: d.lines[base], Lines: map[string]int{}, Doc: di, Root: base}
				if t := tfResourceType(pkg, module, resource); t != "" {
					r.Type = t
					r.Attrs = tfConv(props, tfTypes()[t], "", "", pl, r.Lines)
				} else {
					r.Attrs = props
					r.Lines = pl
				}
				r.Address = r.Type + "." + id
				rs = []*Resource{r}
			}
			for _, r := range rs {
				addr[id] = r.Address
				refs[r] = named
			}
			out = append(out, rs...)
		}
		for r, named := range refs {
			seen := map[string]bool{}
			for _, n := range named {
				if a := addr[n]; a != "" && a != r.Address && !seen[a] {
					seen[a] = true
					r.Refs = append(r.Refs, a)
				}
			}
			sort.Strings(r.Refs)
		}
	}
	return out, syntax
}
