package engine

import (
	"sort"
	"strings"
)

// Compliance mapping is indicative: it shows which controls a finding is
// evidence against, it is not an audit or certification.

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
	"TG-PLAN-001": {"backup", "change"}, "TG-PLAN-002": {"backup", "change"}, "TG-POL-001": {"change"},
}

func complianceReport(fs []Finding) []Framework {
	themeFindings := map[string]int{}
	themeRules := map[string]map[string]bool{}
	for _, f := range fs {
		if f.Waived {
			continue
		}
		for _, t := range ruleThemes[f.RuleID] {
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
	for _, t := range ruleThemes[id] {
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
