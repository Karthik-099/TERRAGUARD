package engine

import "sort"

// foreignRules maps Checkov and Trivy check IDs to the TerraGuard rules that
// cover the same control, so `checkov:skip=` and `trivy:ignore:` comments
// written for those tools keep working. Generated from the cross-references in
// the rule sources; extend it when a rule gains one.
var foreignRules = map[string][]string{
	"AVD-AWS-0013":  {"TG-AWS-CDN-002"},
	"CKV2_AWS_12":   {"TG-AWS-SG-002"},
	"CKV2_AWS_34":   {"TG-AWS-SSM-001"},
	"CKV2_AWS_52":   {"TG-AWS-OS-001"},
	"CKV2_AZURE_27": {"TG-AZ-SQL-002"},
	"CKV2_AZURE_40": {"TG-AZ-ST-003"},
	"CKV2_AZURE_57": {"TG-AZ-DB-002"},
	"CKV2_GCP_6":    {"TG-GCP-IAM-004"},
	"CKV_AWS_122":   {"TG-AWS-SAGEMAKER-001"},
	"CKV_AWS_129":   {"TG-AWS-RDS-004"},
	"CKV_AWS_161":   {"TG-AWS-RDS-004"},
	"CKV_AWS_205":   {"TG-AWS-EC2-002"},
	"CKV_AWS_228":   {"TG-AWS-OS-001"},
	"CKV_AWS_231":   {"TG-AWS-NACL-001"},
	"CKV_AWS_238":   {"TG-AWS-GD-001"},
	"CKV_AWS_251":   {"TG-AWS-CT-002"},
	"CKV_AWS_286":   {"TG-AWS-IAM-006"},
	"CKV_AWS_289":   {"TG-AWS-IAM-006"},
	"CKV_AWS_301":   {"TG-AWS-LAMBDA-003"},
	"CKV_AWS_302":   {"TG-AWS-RDS-005"},
	"CKV_AWS_307":   {"TG-AWS-SAGEMAKER-001"},
	"CKV_AWS_311":   {"TG-AWS-CODEBUILD-001"},
	"CKV_AWS_35":    {"TG-AWS-CT-002"},
	"CKV_AWS_352":   {"TG-AWS-NACL-001"},
	"CKV_AWS_358":   {"TG-AWS-IAM-007"},
	"CKV_AWS_364":   {"TG-AWS-LAMBDA-003"},
	"CKV_AWS_43":    {"TG-AWS-KINESIS-001"},
	"CKV_AWS_44":    {"TG-AWS-NEPTUNE-001"},
	"CKV_AWS_68":    {"TG-AWS-CDN-002"},
	"CKV_AWS_69":    {"TG-AWS-MQ-001"},
	"CKV_AWS_74":    {"TG-AWS-DOCDB-001"},
	"CKV_AWS_76":    {"TG-AWS-APIGW-002"},
	"CKV_AWS_78":    {"TG-AWS-CODEBUILD-001"},
	"CKV_AWS_81":    {"TG-AWS-MSK-001"},
	"CKV_AWS_88":    {"TG-AWS-EC2-003"},
	"CKV_AWS_89":    {"TG-AWS-DMS-001"},
	"CKV_AWS_9":     {"TG-AWS-IAM-008"},
	"CKV_AWS_90":    {"TG-AWS-DOCDB-001"},
	"CKV_AWS_91":    {"TG-AWS-LB-003"},
	"CKV_AZURE_109": {"TG-AZ-KV-002"},
	"CKV_AZURE_113": {"TG-AZ-SQL-002"},
	"CKV_AZURE_138": {"TG-AZ-ACR-002"},
	"CKV_AZURE_140": {"TG-AZ-COSMOS-001"},
	"CKV_AZURE_141": {"TG-AZ-AKS-002"},
	"CKV_AZURE_203": {"TG-AZ-MSG-001"},
	"CKV_AZURE_204": {"TG-AZ-MSG-001"},
	"CKV_AZURE_34":  {"TG-AZ-ST-004"},
	"CKV_AZURE_35":  {"TG-AZ-ST-005"},
	"CKV_AZURE_39":  {"TG-AZ-IAM-001"},
	"CKV_AZURE_7":   {"TG-AZ-AKS-002"},
	"CKV_AZURE_91":  {"TG-AZ-REDIS-001"},
	"CKV_AZURE_99":  {"TG-AZ-COSMOS-001"},
	"CKV_GCP_1":     {"TG-GCP-GKE-003"},
	"CKV_GCP_112":   {"TG-GCP-IAM-004"},
	"CKV_GCP_114":   {"TG-GCP-GCS-002"},
	"CKV_GCP_118":   {"TG-GCP-IAM-005"},
	"CKV_GCP_125":   {"TG-GCP-IAM-005"},
	"CKV_GCP_13":    {"TG-GCP-GKE-003"},
	"CKV_GCP_14":    {"TG-GCP-SQL-002"},
	"CKV_GCP_32":    {"TG-GCP-VM-003"},
	"CKV_GCP_34":    {"TG-GCP-VM-003"},
	"CKV_GCP_36":    {"TG-GCP-VM-004"},
	"CKV_GCP_4":     {"TG-GCP-LB-001"},
	"CKV_GCP_40":    {"TG-GCP-VM-004"},
	"CKV_GCP_41":    {"TG-GCP-IAM-002"},
	"CKV_GCP_42":    {"TG-GCP-IAM-003"},
	"CKV_GCP_46":    {"TG-GCP-IAM-003"},
	"CKV_GCP_49":    {"TG-GCP-IAM-002"},
	"CKV_GCP_50":    {"TG-GCP-SQL-003"},
	"CKV_GCP_64":    {"TG-GCP-GKE-004"},
	"CKV_GCP_69":    {"TG-GCP-GKE-002"},
	"CKV_GCP_71":    {"TG-GCP-GKE-004"},
	"CKV_GCP_95":    {"TG-GCP-REDIS-001"},
	"CKV_GCP_97":    {"TG-GCP-REDIS-001"},
	"CKV_K8S_23":    {"TG-K8S-005"},
	"CKV_K8S_27":    {"TG-K8S-004"},
	"CKV_K8S_39":    {"TG-K8S-006"},
	"CKV_K8S_49":    {"TG-K8S-008"},
	"KSV005":        {"TG-K8S-006"},
	"KSV012":        {"TG-K8S-005"},
	"KSV023":        {"TG-K8S-004"},
	"KSV044":        {"TG-K8S-008"},
	"KSV111":        {"TG-K8S-007"},
}

// AliasesOf lists the other tools' check IDs that map to a rule, so their
// skip comments apply to it.
func AliasesOf(id string) []string {
	var out []string
	for ref, ids := range foreignRules {
		for _, x := range ids {
			if x == id {
				out = append(out, ref)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
