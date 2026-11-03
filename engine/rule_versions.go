package engine

import (
	"strconv"
	"strings"
)

// RulesVersion is the rule set this build ships. A policy can pin
// rules_version to an older set so an upgrade never fails CI overnight:
// findings from newer rules are still reported, but they do not gate.
const RulesVersion = "2.1"

// rulesV20 are the rules released in v2.0.0. When a release ships, its new
// rules get their own list here; anything unlisted is RulesVersion.
var rulesV20 = map[string]bool{}

func init() {
	for _, id := range []string{
		"TG-ALI-001", "TG-AWS-CACHE-001", "TG-AWS-CDN-001", "TG-AWS-CT-001", "TG-AWS-DDB-001", "TG-AWS-EBS-001",
		"TG-AWS-EC2-001", "TG-AWS-ECR-001", "TG-AWS-EKS-001", "TG-AWS-IAM-001", "TG-AWS-IAM-002", "TG-AWS-IAM-003",
		"TG-AWS-KMS-001", "TG-AWS-LAMBDA-001", "TG-AWS-LAMBDA-002", "TG-AWS-LB-001", "TG-AWS-MSG-001",
		"TG-AWS-RDS-001", "TG-AWS-RDS-002", "TG-AWS-RDS-003", "TG-AWS-S3-001", "TG-AWS-S3-002", "TG-AWS-S3-003",
		"TG-AWS-SG-001", "TG-AWS-VPC-001", "TG-AZ-AKS-001", "TG-AZ-KV-001", "TG-AZ-NSG-001", "TG-AZ-SQL-001",
		"TG-AZ-ST-001", "TG-CDN-001", "TG-CF-001", "TG-CF-002", "TG-CF-003", "TG-COST-001", "TG-COST-002",
		"TG-COST-003", "TG-DNS-001", "TG-DNS-002", "TG-DNS-003", "TG-DO-DB-001", "TG-DO-DROPLET-001",
		"TG-DO-FW-001", "TG-DO-SPACES-001", "TG-GCP-FW-001", "TG-GCP-GCS-001", "TG-GCP-GKE-001", "TG-GCP-IAM-001",
		"TG-GCP-SQL-001", "TG-GCP-VM-001", "TG-HELM-001", "TG-HZ-FW-001", "TG-HZ-SRV-001", "TG-K8S-001",
		"TG-K8S-002", "TG-K8S-003", "TG-LIN-FW-001", "TG-OCI-NET-001", "TG-OCI-OS-001", "TG-OS-SG-001",
		"TG-OVH-DB-001", "TG-PATH-001", "TG-PATH-002", "TG-PATH-003", "TG-PLAN-001", "TG-PLAN-002", "TG-POL-001",
		"TG-SEC-001", "TG-SEC-002", "TG-SEC-003", "TG-STATE-001", "TG-STATE-002", "TG-STATE-003", "TG-TF-001",
		"TG-TF-002", "TG-TF-003", "TG-TF-004", "TG-TF-010", "TG-VAL-001", "TG-VAL-002", "TG-VAL-003", "TG-VAL-004",
		"TG-VAL-005", "TG-VAL-006", "TG-VAL-007", "TG-VAL-008", "TG-VAL-009", "TG-VAL-010", "TG-VULTR-001",
	} {
		rulesV20[id] = true
	}
}

// RuleSince returns the rule set version that introduced a rule.
func RuleSince(id string) string {
	if rulesV20[id] || strings.HasPrefix(id, "ORG-") || !strings.HasPrefix(id, "TG-") {
		return "2.0"
	}
	return RulesVersion
}

// newerThan compares "major.minor" versions.
func newerThan(a, b string) bool {
	pa, pb := strings.SplitN(a, ".", 2), strings.SplitN(b, ".", 2)
	for i := 0; i < 2; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}
