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
	Import  int          `json:"import"`
	Moved   int          `json:"moved"`
	Changes []PlanChange `json:"changes"`
	Outputs []PlanChange `json:"outputs,omitempty"` // output values that change
	Drift   []PlanChange `json:"drift,omitempty"`   // changed outside Terraform; Reasons lists the attributes
}

type PlanChange struct {
	Address string   `json:"address"`
	Type    string   `json:"type"`
	Action  string   `json:"action"` // create | update | delete | replace | read | no-op
	Reasons []string `json:"reasons,omitempty"`
	From    string   `json:"from,omitempty"` // previous address when moved
}

type tfChange struct {
	Address         string `json:"address"`
	PreviousAddress string `json:"previous_address"`
	Mode            string `json:"mode"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	Change          struct {
		Actions      []string       `json:"actions"`
		Before       map[string]any `json:"before"`
		After        map[string]any `json:"after"`
		ReplacePaths [][]any        `json:"replace_paths"`
		Importing    any            `json:"importing"`
	} `json:"change"`
}

type tfPlan struct {
	FormatVersion   string     `json:"format_version"`
	ResourceChanges []tfChange `json:"resource_changes"`
	ResourceDrift   []tfChange `json:"resource_drift"`
	OutputChanges   map[string]struct {
		Actions []string `json:"actions"`
	} `json:"output_changes"`
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
		if rc.Change.Importing != nil {
			sum.Import++
		}
		if rc.PreviousAddress != "" && rc.PreviousAddress != rc.Address {
			sum.Moved++
		}
		if action != "no-op" || rc.Change.Importing != nil || rc.PreviousAddress != "" {
			sum.Changes = append(sum.Changes, PlanChange{Address: rc.Address, Type: rc.Type, Action: action, Reasons: reasons, From: rc.PreviousAddress})
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
	for _, name := range sortedKeys(p.OutputChanges) {
		if a := strings.Join(p.OutputChanges[name].Actions, ","); a != "no-op" {
			sum.Outputs = append(sum.Outputs, PlanChange{Address: "output." + name, Action: a})
		}
	}
	planned := map[string]string{}
	for _, rc := range p.ResourceChanges {
		planned[rc.Address] = strings.Join(rc.Change.Actions, ",")
	}
	for _, d := range p.ResourceDrift {
		changed := driftedAttributes(d.Change.Before, d.Change.After)
		action := strings.Join(d.Change.Actions, ",")
		sum.Drift = append(sum.Drift, PlanChange{Address: d.Address, Type: d.Type, Action: action, Reasons: changed})
		msg := d.Address + " was changed outside Terraform"
		if action == "delete" {
			msg = d.Address + " was deleted outside Terraform"
		} else if len(changed) > 0 {
			msg += " (" + strings.Join(changed, ", ") + ")"
		}
		sev, tail := Low, ". This apply will put it back to what the code says."
		if statefulTypes[d.Type] || action == "delete" {
			sev = Medium
		}
		if a, ok := planned[d.Address]; ok && (a == "no-op" || a == "read") {
			// Covered by ignore_changes, or the change does not matter to the code.
			sev, tail = Info, ". This plan leaves it as it is (for example ignore_changes)."
		}
		out = append(out, newFinding("TG-PLAN-003", sev, msg+tail, d.Address, "plan.json", 0))
	}
	return sum, res, out, nil
}

// driftedAttributes lists the top-level attributes whose live value differs
// from what Terraform last recorded.
func driftedAttributes(before, after map[string]any) []string {
	var out []string
	for _, k := range sortedKeys(before) {
		if fmt.Sprint(before[k]) != fmt.Sprint(after[k]) {
			out = append(out, k)
		}
	}
	for _, k := range sortedKeys(after) {
		if _, ok := before[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}
