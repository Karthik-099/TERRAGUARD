package engine

import (
	"sort"
	"strings"
)

// Compliance mapping is indicative, not an audit.

type Framework struct {
	Name     string    `json:"name"`
	Controls []Control `json:"controls"`
	Passing  int       `json:"passing"`
	Total    int       `json:"total"`
}

type Control struct {
	ID       string   `json:"id"`
	Theme    string   `json:"theme"`
	Findings int      `json:"findings"`
	Rules    []string `json:"rules,omitempty"`
}

var themeTitles = map[string]string{
	"encryption-at-rest": "Encryption at rest", "encryption-in-transit": "Encryption in transit",
	"network": "Network exposure", "access": "Least privilege & access control", "secrets": "Secrets & credentials",
	"logging": "Audit logging", "backup": "Backup & recovery", "change": "Change & supply-chain integrity",
}

// frameworks maps theme -> control ID for each framework.
var frameworks = []struct {
	name     string
	controls map[string]string
}{
	{"CIS Controls v8", map[string]string{"encryption-at-rest": "3.11", "encryption-in-transit": "3.10", "network": "4.4", "access": "5.4 / 6.8", "logging": "8.2", "backup": "11.2", "change": "16.4", "secrets": "3.3"}},
	{"SOC 2 (TSC 2017)", map[string]string{"encryption-at-rest": "CC6.1", "encryption-in-transit": "CC6.7", "network": "CC6.6", "access": "CC6.3", "secrets": "CC6.1", "logging": "CC7.2", "backup": "A1.2", "change": "CC8.1"}},
	{"PCI DSS v4.0", map[string]string{"encryption-at-rest": "3.5", "encryption-in-transit": "4.2", "network": "1.3", "access": "7.2", "secrets": "8.3", "logging": "10.2", "change": "6.3"}},
	{"ISO/IEC 27001:2022", map[string]string{"encryption-at-rest": "A.8.24", "encryption-in-transit": "A.8.24", "network": "A.8.20", "access": "A.5.15", "secrets": "A.5.17", "logging": "A.8.15", "backup": "A.8.13", "change": "A.8.32"}},
	{"HIPAA Security Rule", map[string]string{"encryption-at-rest": "164.312(a)(2)(iv)", "encryption-in-transit": "164.312(e)(1)", "network": "164.312(e)(1)", "access": "164.312(a)(1)", "secrets": "164.312(d)", "logging": "164.312(b)", "backup": "164.308(a)(7)"}},
}

// ruleThemes assigns rules to control themes; prefixes match rule families.
var ruleThemes = map[string][]string{
	"TG-AWS-S3-001": {"network", "access"}, "TG-AWS-S3-002": {"access"}, "TG-AWS-S3-003": {"backup"},
	"TG-AWS-SG-001": {"network"}, "TG-AWS-RDS-001": {"network"}, "TG-AWS-RDS-002": {"encryption-at-rest"}, "TG-AWS-RDS-003": {"backup"},
	"TG-AWS-EBS-001": {"encryption-at-rest"}, "TG-AWS-DDB-001": {"backup"}, "TG-AWS-EC2-001": {"access"},
	"TG-AWS-LAMBDA-001": {"access"}, "TG-AWS-LAMBDA-002": {"change"}, "TG-AWS-EKS-001": {"network"},
	"TG-AWS-IAM-001": {"access"}, "TG-AWS-IAM-002": {"access"}, "TG-AWS-IAM-003": {"access"},
	"TG-AWS-KMS-001": {"encryption-at-rest"}, "TG-AWS-CT-001": {"logging"}, "TG-AWS-LB-001": {"encryption-in-transit"},
	"TG-AWS-CDN-001": {"encryption-in-transit"}, "TG-AWS-MSG-001": {"encryption-at-rest"}, "TG-AWS-ECR-001": {"change"},
	"TG-AWS-CACHE-001": {"encryption-at-rest", "encryption-in-transit"}, "TG-AWS-VPC-001": {"logging"},
	"TG-GCP-GCS-001": {"access"}, "TG-GCP-FW-001": {"network"}, "TG-GCP-SQL-001": {"network", "encryption-in-transit"},
	"TG-GCP-IAM-001": {"access"}, "TG-GCP-GKE-001": {"network", "access"}, "TG-GCP-VM-001": {"access"},
	"TG-AZ-ST-001": {"encryption-in-transit", "access"}, "TG-AZ-NSG-001": {"network"}, "TG-AZ-KV-001": {"backup"},
	"TG-AZ-SQL-001": {"network"}, "TG-AZ-AKS-001": {"network", "access"},
	"TG-CF-001": {"encryption-in-transit"}, "TG-CF-002": {"network"}, "TG-CF-003": {"secrets"},
	"TG-DO-FW-001": {"network"}, "TG-DO-SPACES-001": {"access"}, "TG-DO-DROPLET-001": {"access"}, "TG-DO-DB-001": {"network"},
	"TG-LIN-FW-001": {"network"}, "TG-HZ-FW-001": {"network"}, "TG-HZ-SRV-001": {"network"}, "TG-OS-SG-001": {"network"},
	"TG-OVH-DB-001": {"network"}, "TG-OCI-NET-001": {"network"}, "TG-OCI-OS-001": {"access"}, "TG-ALI-001": {"network", "access"},
	"TG-VULTR-001": {"network"}, "TG-K8S-001": {"access"}, "TG-K8S-002": {"change"}, "TG-K8S-003": {"network"}, "TG-HELM-001": {"change"},
	"TG-SEC-001": {"secrets"}, "TG-SEC-002": {"secrets"}, "TG-SEC-003": {"secrets", "logging"},
	"TG-TF-001": {"change"}, "TG-TF-002": {"change"}, "TG-STATE-001": {"encryption-at-rest", "backup"}, "TG-STATE-002": {"secrets"},
	"TG-DNS-001": {"change"}, "TG-DNS-002": {"network"}, "TG-DNS-003": {"network"}, "TG-CDN-001": {"encryption-in-transit"},
	"TG-PATH-001": {"network"}, "TG-PATH-002": {"access"}, "TG-PATH-003": {"access", "network"},
	"TG-AWS-EFS-001": {"encryption-at-rest"}, "TG-AWS-REDSHIFT-001": {"network", "encryption-at-rest"}, "TG-AWS-APIGW-001": {"access"},
	"TG-AWS-LB-002": {"network"}, "TG-AWS-ECS-001": {"access", "secrets"}, "TG-AWS-CW-001": {"logging"}, "TG-AWS-SUBNET-001": {"network"},
	"TG-AWS-EKS-002": {"encryption-at-rest", "logging"}, "TG-AWS-IAM-004": {"access", "secrets"}, "TG-AZ-VM-001": {"access"},
	"TG-AZ-APP-001": {"encryption-in-transit"}, "TG-AZ-DB-001": {"encryption-in-transit"}, "TG-AZ-ACR-001": {"access", "secrets"},
	"TG-GCP-BQ-001": {"access"}, "TG-GCP-KMS-001": {"encryption-at-rest"}, "TG-GCP-NET-001": {"logging"}, "TG-GCP-VM-002": {"access"},
	"TG-GH-001": {"change", "access"}, "TG-GH-002": {"secrets"}, "TG-DO-K8S-001": {"change"},
	"TG-AWS-RDS-004": {"logging", "access"}, "TG-AWS-RDS-005": {"access"}, "TG-AWS-DOCDB-001": {"encryption-at-rest", "encryption-in-transit"},
	"TG-AWS-NEPTUNE-001": {"encryption-at-rest"}, "TG-AWS-MQ-001": {"network"}, "TG-AWS-DMS-001": {"network"}, "TG-AWS-SAGEMAKER-001": {"network", "access"},
	"TG-AWS-KINESIS-001": {"encryption-at-rest"}, "TG-AWS-MSK-001": {"encryption-in-transit", "access", "network"}, "TG-AWS-OS-001": {"access", "encryption-in-transit"},
	"TG-AWS-IAM-006": {"access"}, "TG-AWS-IAM-007": {"access"}, "TG-AWS-IAM-008": {"access", "secrets"}, "TG-AWS-LAMBDA-003": {"access"},
	"TG-AWS-CT-002": {"logging", "encryption-at-rest"}, "TG-AWS-GD-001": {"logging"}, "TG-AWS-EC2-002": {"access"}, "TG-AWS-EC2-003": {"network"},
	"TG-AWS-SG-002": {"network"}, "TG-AWS-NACL-001": {"network"}, "TG-AWS-APIGW-002": {"logging"}, "TG-AWS-LB-003": {"logging"},
	"TG-AWS-CODEBUILD-001": {"encryption-at-rest", "change"}, "TG-AWS-SSM-001": {"secrets"}, "TG-AWS-CDN-002": {"encryption-in-transit"},
	"TG-AZ-ST-003": {"access", "secrets"}, "TG-AZ-ST-004": {"access"}, "TG-AZ-ST-005": {"network"}, "TG-AZ-KV-002": {"network"},
	"TG-AZ-SQL-002": {"network", "access"}, "TG-AZ-DB-002": {"network"}, "TG-AZ-COSMOS-001": {"network", "access"}, "TG-AZ-REDIS-001": {"encryption-in-transit"},
	"TG-AZ-ACR-002": {"access"}, "TG-AZ-AKS-002": {"access", "network"}, "TG-AZ-IAM-001": {"access"}, "TG-AZ-MSG-001": {"access", "secrets"},
	"TG-GCP-GKE-002": {"access", "secrets"}, "TG-GCP-GKE-003": {"access", "logging"}, "TG-GCP-GKE-004": {"network"}, "TG-GCP-SQL-002": {"backup"},
	"TG-GCP-SQL-003": {"access"}, "TG-GCP-GCS-002": {"access"}, "TG-GCP-VM-003": {"access"}, "TG-GCP-VM-004": {"network"},
	"TG-GCP-IAM-002": {"access"}, "TG-GCP-IAM-003": {"access"}, "TG-GCP-IAM-004": {"access"}, "TG-GCP-IAM-005": {"access"},
	"TG-GCP-LB-001": {"encryption-in-transit"}, "TG-GCP-REDIS-001": {"access", "encryption-in-transit"},
	"TG-K8S-004": {"access"}, "TG-K8S-005": {"access"}, "TG-K8S-006": {"access"}, "TG-K8S-007": {"access"}, "TG-K8S-008": {"access"},
	"TG-SCHEMA-001": {"change"}, "TG-SCHEMA-002": {"change"}, "TG-SCHEMA-003": {"change"},
	"TG-PLAN-001": {"backup", "change"}, "TG-PLAN-002": {"backup", "change"}, "TG-POL-001": {"change"}, "TG-POL-002": {"change"},
}

func complianceReport(fs []Finding) []Framework {
	themeFindings := map[string]int{}
	themeRules := map[string]map[string]bool{}
	for _, f := range fs {
		if f.Waived {
			continue
		}
		for _, t := range themesOf(f.RuleID) {
			themeFindings[t]++
			if themeRules[t] == nil {
				themeRules[t] = map[string]bool{}
			}
			themeRules[t][f.RuleID] = true
		}
	}
	var out []Framework
	for _, fw := range frameworks {
		f := Framework{Name: fw.name}
		themes := make([]string, 0, len(fw.controls))
		for t := range fw.controls {
			themes = append(themes, t)
		}
		sort.Strings(themes)
		for _, t := range themes {
			var rules []string
			for r := range themeRules[t] {
				rules = append(rules, r)
			}
			sort.Strings(rules)
			c := Control{ID: fw.controls[t], Theme: themeTitles[t], Findings: themeFindings[t], Rules: rules}
			if c.Findings == 0 {
				f.Passing++
			}
			f.Controls = append(f.Controls, c)
			f.Total++
		}
		out = append(out, f)
	}
	return out
}

// ThemesFor exposes the mapping for the rule catalog.
func ThemesFor(id string) []string {
	var out []string
	for _, t := range themesOf(id) {
		out = append(out, themeTitles[t])
	}
	return out
}

// providerOf returns the Terraform provider prefix of a resource address.
func providerOf(addr string) string {
	addr = strings.TrimPrefix(addr, "data.")
	p, _, _ := strings.Cut(addr, "_")
	if strings.Contains(p, ".") {
		return ""
	}
	return p
}

// Rules without an explicit entry are mapped by their CWE.
var cweThemes = map[string][]string{
	"CWE-311": {"encryption-at-rest"}, "CWE-312": {"encryption-at-rest", "secrets"},
	"CWE-319": {"encryption-in-transit"}, "CWE-326": {"encryption-in-transit"}, "CWE-327": {"encryption-in-transit"}, "CWE-298": {"encryption-in-transit"},
	"CWE-284": {"network", "access"}, "CWE-306": {"access"}, "CWE-287": {"access"}, "CWE-308": {"access"}, "CWE-250": {"access"},
	"CWE-269": {"access"}, "CWE-732": {"access"}, "CWE-918": {"access"}, "CWE-200": {"access"}, "CWE-668": {"access"},
	"CWE-778": {"logging"}, "CWE-779": {"logging"}, "CWE-693": {"change"}, "CWE-1104": {"change"}, "CWE-489": {"change"},
	"CWE-798": {"secrets"}, "CWE-526": {"secrets"}, "CWE-324": {"encryption-at-rest"},
}

func themesOf(id string) []string {
	if t, ok := ruleThemes[id]; ok {
		return t
	}
	if r := ruleIndex[id]; r != nil {
		return cweThemes[r.CWE]
	}
	return nil
}
