package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ruleIDs runs the built-in and Deployment Manager rules on resources.
func ruleIDs(rs []*Resource) map[string]bool {
	ids := map[string]bool{}
	for _, r := range rs {
		for _, rule := range concatRules(Rules, gdmRules) {
			if rule.applies(r.Type) && len(rule.Check(r)) > 0 {
				ids[rule.ID] = true
			}
		}
	}
	return ids
}

func TestPulumiCrossplaneGDMEvalCases(t *testing.T) {
	files, _ := filepath.Glob("../evals/cases/*")
	parsers := map[string]formatParser{"pulumi_": parsePulumi, "crossplane_": parseCrossplane, "gdm_": parseGDM}
	for _, f := range files {
		base := filepath.Base(f)
		var parse formatParser
		for p, fn := range parsers {
			if strings.HasPrefix(base, p) {
				parse = fn
			}
		}
		if parse == nil {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		rs, syntax := parse(base, string(src))
		if len(syntax) > 0 || len(rs) == 0 {
			t.Fatalf("%s: %d resources, syntax %v", base, len(rs), syntax)
		}
		got := ruleIDs(rs)
		if os.Getenv("DUMP") != "" {
			var l []string
			for id := range got {
				l = append(l, id)
			}
			sort.Strings(l)
			for _, r := range rs {
				t.Logf("%s %s", base, r.Address)
			}
			t.Logf("%s fires: %s", base, strings.Join(l, ", "))
		}
		for _, line := range strings.Split(string(src), "\n") {
			for _, h := range []string{"# expect:", "# forbid:"} {
				rest, ok := strings.CutPrefix(line, h)
				if !ok {
					continue
				}
				for _, id := range strings.Split(rest, ",") {
					id = strings.TrimSpace(id)
					if id != "" && got[id] != (h == "# expect:") {
						t.Errorf("%s: %s %s", base, h, id)
					}
				}
			}
		}
	}
}

func TestTerraformTypeMapping(t *testing.T) {
	cases := map[string]string{
		"aws:s3/bucket:Bucket": "aws_s3_bucket", "aws:s3:BucketV2": "aws_s3_bucket", "aws:ec2/securityGroup:SecurityGroup": "aws_security_group",
		"aws:rds/instance:Instance": "aws_db_instance", "aws:rds:Cluster": "aws_rds_cluster", "aws:rds:SubnetGroup": "aws_db_subnet_group",
		"aws:ec2:Instance": "aws_instance", "aws:ec2:Vpc": "aws_vpc", "aws:ebs:Volume": "aws_ebs_volume", "aws:iam:Role": "aws_iam_role",
		"aws:lambda:Function": "aws_lambda_function", "aws:apigateway:RestApi": "aws_api_gateway_rest_api", "aws:alb:LoadBalancer": "aws_lb",
		"aws:cloudtrail:Trail": "aws_cloudtrail", "aws:kms:Key": "aws_kms_key", "aws:dynamodb:Table": "aws_dynamodb_table",
		"aws:elasticache:ReplicationGroup": "aws_elasticache_replication_group", "aws:eks:Cluster": "aws_eks_cluster",
		"gcp:storage/bucket:Bucket": "google_storage_bucket", "gcp:compute:Instance": "google_compute_instance", "gcp:compute:Firewall": "google_compute_firewall",
		"gcp:sql:DatabaseInstance": "google_sql_database_instance", "gcp:container:Cluster": "google_container_cluster",
		"gcp:projects:IAMMember": "google_project_iam_member", "gcp:organizations:Project": "google_project", "gcp:serviceaccount:Account": "google_service_account",
		"gcp:storage:BucketIAMBinding": "google_storage_bucket_iam_binding", "gcp:cloudrunv2:Service": "google_cloud_run_v2_service",
		"azure:storage/account:Account": "azurerm_storage_account", "azure:compute:LinuxVirtualMachine": "azurerm_linux_virtual_machine",
		"azure:network:NetworkSecurityGroup": "azurerm_network_security_group", "azure:network:VirtualNetwork": "azurerm_virtual_network",
		"azure:keyvault:KeyVault": "azurerm_key_vault", "azure:keyvault:Secret": "azurerm_key_vault_secret", "azure:core:ResourceGroup": "azurerm_resource_group",
		"azure:containerservice:KubernetesCluster": "azurerm_kubernetes_cluster", "azure:monitoring:DiagnosticSetting": "azurerm_monitor_diagnostic_setting",
		// Crossplane Upbound groups and kinds
		"aws:elbv2:LB": "aws_lb", "aws:elbv2:LBListener": "aws_lb_listener", "aws:ec2:SecurityGroupIngressRule": "aws_vpc_security_group_ingress_rule",
		"gcp:cloudplatform:ServiceAccount": "google_service_account", "gcp:cloudplatform:ProjectIAMMember": "google_project_iam_member",
		"azure:keyvault:Vault": "azurerm_key_vault", "azure::ResourceGroup": "azurerm_resource_group",
		// unknown: no guess
		"aws:nosuch:Thing": "", "aws-native:s3:Bucket": "",
	}
	for tok, want := range cases {
		parts := strings.Split(tok, ":")
		module, _, _ := strings.Cut(parts[1], "/")
		if got := tfResourceType(parts[0], module, parts[2]); got != want {
			t.Errorf("%s: got %q, want %q", tok, got, want)
		}
	}
}

func TestPulumiConversion(t *testing.T) {
	src := `name: x
runtime: yaml
resources:
  b:
    type: aws:s3:Bucket
    properties:
      bucket: ${prefix}-data
      tags:
        Team: data
      serverSideEncryptionConfiguration:
        rule:
          applyServerSideEncryptionByDefault:
            sseAlgorithm: aws:kms
  vm:
    type: gcp:compute:Instance
    properties:
      networkInterfaces:
        - network: ${net.id}
          accessConfigs: [{}]
  net:
    type: gcp:compute:Network
  ext:
    type: aws:s3:Bucket
    get:
      id: existing
`
	rs, syntax := parsePulumi("Pulumi.yaml", src)
	if len(syntax) > 0 || len(rs) != 3 {
		t.Fatalf("got %d resources, %v", len(rs), syntax)
	}
	byName := map[string]*Resource{}
	for _, r := range rs {
		byName[r.Name] = r
	}
	b := byName["b"]
	if !isUnknown(b.get("bucket")) || b.get("tags.Team") != "data" {
		t.Errorf("bucket attrs: %#v", b.Attrs)
	}
	if b.get("server_side_encryption_configuration.0.rule.0.apply_server_side_encryption_by_default.0.sse_algorithm") != "aws:kms" {
		t.Errorf("nested blocks: %#v", b.Attrs)
	}
	if b.line("tags.Team") != 9 {
		t.Errorf("line of tags.Team = %d", b.line("tags.Team"))
	}
	vm := byName["vm"]
	if _, ok := vm.Attrs["network_interface"].([]any); !ok || len(vm.Refs) != 1 || vm.Refs[0] != "google_compute_network.net" {
		t.Errorf("vm: %#v refs %v", vm.Attrs, vm.Refs)
	}
	if !isPulumiFile("pulumi.yaml", src) || isPulumiFile("pulumi.yaml", "name: x\nruntime: go\n") {
		t.Error("isPulumiFile")
	}
}

func TestCrossplaneConversion(t *testing.T) {
	src := `apiVersion: apiextensions.crossplane.io/v1
kind: Composition
metadata:
  name: db
spec:
  resources:
    - name: rds
      base:
        apiVersion: rds.aws.upbound.io/v1beta1
        kind: Instance
        spec:
          forProvider:
            region: us-east-1
            storageEncrypted: false
            dbSubnetGroupNameSelector:
              matchLabels: {app: db}
      patches:
        - fromFieldPath: spec.public
          toFieldPath: spec.forProvider.publiclyAccessible
---
apiVersion: s3.aws.m.upbound.io/v1beta1
kind: Bucket
metadata:
  name: b
spec:
  initProvider:
    forceDestroy: true
  forProvider:
    region: us-east-1
---
apiVersion: database.aws.crossplane.io/v1beta1
kind: RDSInstance
metadata:
  name: contrib
spec:
  forProvider:
    publiclyAccessible: true
`
	rs, syntax := parseCrossplane("x.yaml", src)
	if len(syntax) > 0 || len(rs) != 3 {
		t.Fatalf("got %d resources, %v", len(rs), syntax)
	}
	db, b, c := rs[0], rs[1], rs[2]
	if db.Address != "aws_db_instance.db.rds" || !isUnknown(db.get("publicly_accessible")) || !isUnknown(db.get("db_subnet_group_name")) || db.get("storage_encrypted") != false {
		t.Errorf("composed db: %s %#v", db.Address, db.Attrs)
	}
	if db.line("storage_encrypted") != 14 {
		t.Errorf("line of storage_encrypted = %d", db.line("storage_encrypted"))
	}
	if b.Type != "aws_s3_bucket" || b.get("force_destroy") != true {
		t.Errorf("bucket: %s %#v", b.Type, b.Attrs)
	}
	if c.Type != "database.aws.crossplane.io/RDSInstance" {
		t.Errorf("contrib type %s", c.Type)
	}
	if !isCrossplane(src) || isCrossplane("apiVersion: apps/v1\nkind: Deployment\n") {
		t.Error("isCrossplane")
	}
}

func TestGDMParseAndDetect(t *testing.T) {
	src := `resources:
- name: vm
  type: compute.v1.instance
  properties:
    networkInterfaces:
    - network: $(ref.net.selfLink)
      accessConfigs: $(ref.cfg.list)
- name: net
  type: compute.v1.network
`
	if !isDeploymentManager(src) || isDeploymentManager("resources:\n  b:\n    type: aws:s3:Bucket\n") {
		t.Error("isDeploymentManager")
	}
	rs, _ := parseGDM("d.yaml", src)
	if len(rs) != 2 || rs[0].Type != "gdm_compute_v1_instance" || len(rs[0].Refs) != 1 || rs[0].line("networkInterfaces.0.network") != 6 {
		t.Fatalf("%#v", rs)
	}
	for _, rule := range gdmRules {
		if rule.applies(rs[0].Type) && len(rule.Check(rs[0])) > 0 && rule.ID == "TG-GDM-COMPUTE-001" {
			t.Error("an unknown accessConfigs must not fire")
		}
	}
}
