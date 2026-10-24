package engine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PlanSummary describes what `terraform apply` would do, from `terraform show -json tfplan`.
type PlanSummary struct {
	Create  int          `json:"create"`
	Update  int          `json:"update"`
	Delete  int          `json:"delete"`
	Replace int          `json:"replace"`
	NoOp    int          `json:"no_op"`
	Changes []PlanChange `json:"changes"`
}

type PlanChange struct {
	Address string   `json:"address"`
	Type    string   `json:"type"`
	Action  string   `json:"action"` // create | update | delete | replace | read | no-op
	Reasons []string `json:"reasons,omitempty"`
}

type tfPlan struct {
	FormatVersion   string `json:"format_version"`
	ResourceChanges []struct {
		Address string `json:"address"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Change  struct {
			Actions      []string       `json:"actions"`
			After        map[string]any `json:"after"`
			ReplacePaths [][]any        `json:"replace_paths"`
		} `json:"change"`
	} `json:"resource_changes"`
}

// Stateful resources lose data when destroyed or replaced.
var statefulTypes = map[string]bool{
	"aws_db_instance": true, "aws_rds_cluster": true, "aws_s3_bucket": true, "aws_ebs_volume": true,
	"aws_dynamodb_table": true, "aws_efs_file_system": true, "aws_elasticache_cluster": true,
	"aws_elasticache_replication_group": true, "aws_kms_key": true, "aws_eks_cluster": true,
	"aws_opensearch_domain": true, "aws_elasticsearch_domain": true, "aws_redshift_cluster": true,
	"aws_docdb_cluster": true, "aws_neptune_cluster": true, "aws_secretsmanager_secret": true,
	"aws_route53_zone": true, "aws_cognito_user_pool": true, "aws_msk_cluster": true,
	"google_sql_database_instance": true, "google_storage_bucket": true, "google_container_cluster": true,
	"azurerm_storage_account": true, "azurerm_mssql_database": true, "azurerm_postgresql_flexible_server": true,
	"cloudflare_zone": true, "cloudflare_d1_database": true, "cloudflare_r2_bucket": true, "cloudflare_workers_kv_namespace": true,
}

func parsePlan(raw string) (*PlanSummary, []*Resource, []Finding, error) {
	var p tfPlan
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, nil, nil, fmt.Errorf("plan is not valid JSON: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, nil, nil, fmt.Errorf("not a Terraform JSON plan; produce one with: terraform plan -out tfplan && terraform show -json tfplan > plan.json")
	}
	sum := &PlanSummary{}
	var res []*Resource
	var out []Finding
	for _, rc := range p.ResourceChanges {
		a := rc.Change.Actions
		action := strings.Join(a, ",")
		switch action {
		case "create":
			sum.Create++
		case "update":
			sum.Update++
		case "delete":
			sum.Delete++
		case "delete,create", "create,delete":
			action = "replace"
			sum.Replace++
		case "read":
		default:
			action = "no-op"
			sum.NoOp++
		}
		var reasons []string
		for _, rp := range rc.Change.ReplacePaths {
			var parts []string
			for _, x := range rp {
				parts = append(parts, fmt.Sprint(x))
			}
			reasons = append(reasons, strings.Join(parts, "."))
		}
		if action != "no-op" {
			sum.Changes = append(sum.Changes, PlanChange{Address: rc.Address, Type: rc.Type, Action: action, Reasons: reasons})
		}
		stateful := statefulTypes[rc.Type]
		switch action {
		case "delete":
			sev := Medium
			msg := rc.Address + " will be destroyed."
			if stateful {
				sev, msg = Critical, rc.Address+" will be DESTROYED and it holds data — this is unrecoverable."
			}
			out = append(out, newFinding("TG-PLAN-001", sev, msg, rc.Address, "plan.json", 0))
		case "replace":
			sev := Low
			msg := rc.Address + " will be destroyed and re-created"
			if stateful {
				sev, msg = Critical, rc.Address+" will be destroyed and re-created, losing its data"
			}
			if len(reasons) > 0 {
				msg += " because these attributes force replacement: " + strings.Join(reasons, ", ")
			}
			out = append(out, newFinding("TG-PLAN-002", sev, msg+".", rc.Address, "plan.json", 0))
		}
		if rc.Mode == "managed" && rc.Change.After != nil && (action == "create" || action == "update" || action == "replace") {
			res = append(res, &Resource{Address: rc.Address, Mode: "managed", Type: rc.Type, Name: rc.Name,
				File: "plan.json", Attrs: rc.Change.After, Lines: map[string]int{}, FromPlan: true})
		}
	}
	return sum, res, out, nil
}
