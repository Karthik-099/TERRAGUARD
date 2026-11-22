package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Databricks rules (databricks/databricks provider), also applied to
// Databricks Asset Bundles (format_dab.go), whose jobs, pipelines, clusters
// and warehouses are read as the matching Terraform types. Defaults are from
// the provider source: autotermination_minutes 60, auto_stop_mins 120 (API),
// data_security_mode absent keeps the default security features,
// lifetime_seconds absent means the workspace maximum or no expiry.

const dbxDay = 86400

// dbxSpec is one cluster specification inside a resource, and where it sits.
type dbxSpec struct {
	path  string
	attrs map[string]any
}

// dbxSpecs returns the cluster specifications a resource defines: the cluster
// itself, job and task clusters, pipeline clusters, and the fixed values of a
// cluster policy.
func dbxSpecs(r *Resource) []dbxSpec {
	var out []dbxSpec
	nested := func(prefix string, v any) {
		for i, m := range asMaps(v) {
			out = append(out, dbxSpec{fmt.Sprintf("%s.%d", prefix, i), m})
		}
	}
	switch r.Type {
	case "databricks_cluster":
		out = append(out, dbxSpec{"", r.Attrs})
	case "databricks_job":
		nested("new_cluster", r.Attrs["new_cluster"])
		for _, list := range []string{"job_cluster", "task"} {
			for i, b := range r.blocks(list) {
				nested(fmt.Sprintf("%s.%d.new_cluster", list, i), b["new_cluster"])
			}
		}
	case "databricks_pipeline":
		nested("cluster", r.Attrs["cluster"])
	case "databricks_cluster_policy":
		for _, k := range []string{"definition", "policy_family_definition_overrides"} {
			if spec := policySpec(r.Attrs[k]); len(spec) > 0 {
				out = append(out, dbxSpec{k, spec})
			}
		}
	}
	return out
}

// dbxJSON reads a JSON document given as a string or as jsonencode() data.
func dbxJSON(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(t), &m) == nil {
			return m
		}
	}
	return nil
}

// policySpec turns the "fixed" elements of a cluster policy definition into
// the cluster attributes they force, so the cluster rules read them too.
func policySpec(v any) map[string]any {
	spec, doc := map[string]any{}, dbxJSON(v)
	for _, k := range sortedKeys(doc) {
		e, _ := doc[k].(map[string]any)
		if t, _ := asString(e["type"]); t != "fixed" {
			continue
		}
		val := e["value"]
		switch {
		case strings.HasPrefix(k, "spark_conf.") || strings.HasPrefix(k, "spark_env_vars."):
			attr, key, _ := strings.Cut(k, ".")
			m, _ := spec[attr].(map[string]any)
			if m == nil {
				m = map[string]any{}
				spec[attr] = m
			}
			m[key] = val
		case strings.HasPrefix(k, "init_scripts.") && strings.Contains(k, ".dbfs."):
			l, _ := spec["init_scripts"].([]any)
			spec["init_scripts"] = append(l, map[string]any{"dbfs": []any{map[string]any{"destination": val}}})
		case !strings.Contains(k, "."):
			spec[k] = val
		}
	}
	return spec
}

func specPath(s dbxSpec, attr string) string {
	if s.path == "definition" || s.path == "policy_family_definition_overrides" {
		return s.path
	}
	return join(s.path, attr)
}

var (
	// Spark and Hadoop settings that carry a credential: storage account keys,
	// SAS tokens, OAuth client secrets, S3 secret keys and session tokens, GCS
	// private keys and the external Hive metastore password.
	dbxConfSecretRE = regexp.MustCompile(`(?i)(\.account\.key(\.|$)|\.sas\.|oauth2\.client\.secret|secret\.key$|secretaccesskey$|session\.token$|private\.key$|password$|\.secret$)`)
	dbxEnvSecretRE  = regexp.MustCompile(`(?i)(secret|password|passwd|token|api_?key)`)
	dbxBroadGroups  = map[string]bool{"users": true, "account users": true}
)

// dbxLiteralSecret is true for a value written in the code rather than a
// {{secrets/scope/key}} reference, a variable or a placeholder.
func dbxLiteralSecret(v any) bool {
	s, ok := v.(string)
	s = strings.TrimSpace(s)
	return ok && s != "" && !strings.Contains(s, "{{secrets/") && !placeholder(s)
}

func confSecretHits(conf any, path string, re *regexp.Regexp, what string) []Hit {
	m, _ := conf.(map[string]any)
	var hits []Hit
	for _, k := range sortedKeys(m) {
		if re.MatchString(k) && dbxLiteralSecret(m[k]) {
			hits = append(hits, Hit{Path: path, Msg: fmt.Sprintf("%s %q holds a literal credential; anyone who can read the code, the state or the cluster configuration can use it.", what, k)})
		}
	}
	return hits
}

var dbxClusterTypes = []string{"databricks_cluster", "databricks_job", "databricks_pipeline", "databricks_cluster_policy"}

var databricksRules = []Rule{
	{ID: "TG-DBX-CL-001", Title: "Cluster never terminates when idle", Severity: Low, Category: CatCost,
		Types:       []string{"databricks_cluster", "databricks_cluster_policy"},
		Remediation: "Set autotermination_minutes to 10 or more (the provider default is 60); keep 0 only for clusters that must stay up, and document why.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, s := range dbxSpecs(r) {
				v := s.attrs["autotermination_minutes"]
				if n, ok := asFloat(v); ok && n == 0 {
					h := Hit{Path: specPath(s, "autotermination_minutes"), Msg: "autotermination_minutes = 0 turns automatic termination off, so an idle cluster keeps billing until someone stops it."}
					if s.path == "" {
						h.Fix = fix(60, "Set autotermination_minutes = 60", "autotermination_minutes")
					}
					hits = append(hits, h)
				}
			}
			return hits
		})},
	{ID: "TG-DBX-CL-002", Title: "Cluster runs without user isolation", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"databricks_cluster", "databricks_job", "databricks_cluster_policy"},
		Remediation: `Set data_security_mode = "USER_ISOLATION" (standard) or "SINGLE_USER" (dedicated), or leave it out so the default security features apply.`,
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, s := range dbxSpecs(r) {
				m, _ := asString(s.attrs["data_security_mode"])
				switch strings.ToUpper(m) {
				case "NONE", "NO_ISOLATION":
					hits = append(hits, Hit{Path: specPath(s, "data_security_mode"), Msg: fmt.Sprintf("data_security_mode = %q turns isolation off: users share one process and credentials, nothing goes through Unity Catalog, and one user can read another's data.", m)})
				case "LEGACY_PASSTHROUGH":
					hits = append(hits, Hit{Path: specPath(s, "data_security_mode"), Sev: Low, Msg: `data_security_mode = "LEGACY_PASSTHROUGH" uses deprecated credential passthrough instead of Unity Catalog access control.`})
				}
			}
			return hits
		})},
	{ID: "TG-DBX-CL-003", Title: "Cluster local disk encryption is turned off", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types:       dbxClusterTypes,
		Remediation: "Set enable_local_disk_encryption = true so shuffle and temporary data on the nodes' local disks is encrypted.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, s := range dbxSpecs(r) {
				if is(s.attrs["enable_local_disk_encryption"], false) {
					h := Hit{Path: specPath(s, "enable_local_disk_encryption"), Msg: "enable_local_disk_encryption = false leaves shuffle and temporary data unencrypted on the nodes' local disks."}
					if s.path == "" {
						h.Fix = fix(true, "Set enable_local_disk_encryption = true", "enable_local_disk_encryption")
					}
					hits = append(hits, h)
				}
			}
			return hits
		})},
	{ID: "TG-DBX-CL-004", Title: "Spark configuration holds a literal credential", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types:       append([]string{"databricks_mount", "databricks_sql_global_config"}, dbxClusterTypes...),
		Remediation: "Reference a secret instead: {{secrets/<scope>/<key>}} in spark_conf, spark_env_vars or extra_configs, with the value stored in a databricks_secret_scope; better, use Unity Catalog storage credentials or instance profiles.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			switch r.Type {
			case "databricks_mount":
				return confSecretHits(r.Attrs["extra_configs"], "extra_configs", dbxConfSecretRE, "extra_configs")
			case "databricks_sql_global_config":
				for _, k := range []string{"data_access_config", "sql_config_params"} {
					hits = append(hits, confSecretHits(r.Attrs[k], k, dbxConfSecretRE, k)...)
				}
				return hits
			}
			for _, s := range dbxSpecs(r) {
				hits = append(hits, confSecretHits(s.attrs["spark_conf"], specPath(s, "spark_conf"), dbxConfSecretRE, "spark_conf")...)
				hits = append(hits, confSecretHits(s.attrs["spark_env_vars"], specPath(s, "spark_env_vars"), dbxEnvSecretRE, "spark_env_vars")...)
			}
			return hits
		})},
	{ID: "TG-DBX-CL-005", Title: "Cluster runs an init script from DBFS", Severity: Medium, Category: CatSecurity, CWE: "CWE-732",
		Types:       dbxClusterTypes,
		Remediation: "Store init scripts in a Unity Catalog volume or workspace files (init_scripts { volumes { ... } } or { workspace { ... } }) where you control who can write them; DBFS init scripts are deprecated.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for _, s := range dbxSpecs(r) {
				for i, sc := range asMaps(s.attrs["init_scripts"]) {
					if sc["dbfs"] == nil {
						continue
					}
					p := fmt.Sprintf("%s.%d", specPath(s, "init_scripts"), i)
					if s.path == "definition" || s.path == "policy_family_definition_overrides" {
						p = s.path
					}
					hits = append(hits, Hit{Path: p, Msg: "The init script runs as root on every node from DBFS, which any workspace user can usually write, so one user can run code on clusters used by others. DBFS init scripts are deprecated."})
				}
			}
			return hits
		})},
	{ID: "TG-DBX-SQL-001", Title: "SQL warehouse never stops when idle", Severity: Low, Category: CatCost,
		Types:       []string{"databricks_sql_endpoint"},
		Remediation: "Set auto_stop_mins to 10 or more (the API default is 120).",
		Check: managed(func(r *Resource) []Hit {
			if n, ok := asFloat(r.get("auto_stop_mins")); ok && n == 0 {
				return []Hit{{Path: "auto_stop_mins", Msg: "auto_stop_mins = 0 turns auto stop off, so an idle warehouse keeps billing.",
					Fix: fix(120, "Set auto_stop_mins = 120", "auto_stop_mins")}}
			}
			return nil
		})},
	{ID: "TG-DBX-UC-001", Title: "Broad write or admin privilege granted to all users", Severity: Medium, Category: CatSecurity, CWE: "CWE-732",
		Types:       []string{"databricks_grants", "databricks_grant", "databricks_sql_permissions"},
		Remediation: "Grant ALL_PRIVILEGES, MANAGE, MODIFY and write privileges to a specific group; give `account users` only USE_CATALOG, USE_SCHEMA or SELECT where everyone needs them.",
		Check: managed(func(r *Resource) []Hit {
			var entries []map[string]any
			var paths []string
			switch r.Type {
			case "databricks_grant":
				entries, paths = []map[string]any{r.Attrs}, []string{"principal"}
			default:
				list := "grant"
				if r.Type == "databricks_sql_permissions" {
					list = "privilege_assignments"
				}
				for i, b := range r.blocks(list) {
					entries, paths = append(entries, b), append(paths, fmt.Sprintf("%s.%d", list, i))
				}
			}
			var hits []Hit
			for i, e := range entries {
				p, _ := asString(e["principal"])
				if !dbxBroadGroups[strings.ToLower(strings.TrimSpace(p))] {
					continue
				}
				for _, priv := range asStrings(e["privileges"]) {
					switch u := strings.ToUpper(strings.ReplaceAll(priv, " ", "_")); u {
					case "ALL_PRIVILEGES", "MANAGE":
						hits = append(hits, Hit{Path: paths[i], Sev: High, Msg: fmt.Sprintf("%s is granted to %q, so every user can read, change and re-grant everything under this object.", priv, p)})
					case "MODIFY", "WRITE_FILES", "WRITE_VOLUME":
						hits = append(hits, Hit{Path: paths[i], Msg: fmt.Sprintf("%s is granted to %q, so every user can change or delete the data.", priv, p)})
					}
				}
			}
			return hits
		})},
	{ID: "TG-DBX-UC-002", Title: "Delta Sharing recipient tokens never expire", Severity: Medium, Category: CatSecurity, CWE: "CWE-613",
		Types:       []string{"databricks_metastore"},
		Remediation: "Set delta_sharing_recipient_token_lifetime_in_seconds to a bounded value (the default is 31536000, one year) and rotate recipient tokens.",
		Check: managed(func(r *Resource) []Hit {
			scope, _ := asString(r.get("delta_sharing_scope"))
			if n, ok := asFloat(r.get("delta_sharing_recipient_token_lifetime_in_seconds")); ok && n == 0 && strings.EqualFold(scope, "INTERNAL_AND_EXTERNAL") {
				return []Hit{{Path: "delta_sharing_recipient_token_lifetime_in_seconds", Msg: "External sharing is on and recipient tokens never expire, so a leaked activation link or credential file gives access to the shared data forever."}}
			}
			return nil
		})},
	{ID: "TG-DBX-IAM-001", Title: "All workspace users can manage the object", Severity: Medium, Category: CatSecurity, CWE: "CWE-732",
		Types:       []string{"databricks_permissions"},
		Remediation: "Give CAN_MANAGE to a specific admin group or service principal; give the users group CAN_ATTACH_TO, CAN_RUN, CAN_VIEW or CAN_USE at most.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for i, ac := range r.blocks("access_control") {
				g, _ := asString(ac["group_name"])
				lvl, _ := asString(ac["permission_level"])
				if dbxBroadGroups[strings.ToLower(g)] && (lvl == "CAN_MANAGE" || lvl == "IS_OWNER") {
					hits = append(hits, Hit{Path: fmt.Sprintf("access_control.%d", i), Msg: fmt.Sprintf("%s is given to the %q group, so every user can change, delete or re-permission it.", lvl, g)})
				}
			}
			return hits
		})},
	{ID: "TG-DBX-IAM-002", Title: "All users can use or manage a service principal or group", Severity: Medium, Category: CatSecurity, CWE: "CWE-269",
		Types:       []string{"databricks_access_control_rule_set"},
		Remediation: "Grant roles/servicePrincipal.user, roles/servicePrincipal.manager and roles/group.manager only to specific groups or principals.",
		Check: managed(func(r *Resource) []Hit {
			var hits []Hit
			for i, g := range r.blocks("grant_rules") {
				role, _ := asString(g["role"])
				if role != "roles/servicePrincipal.user" && role != "roles/servicePrincipal.manager" && role != "roles/group.manager" {
					continue
				}
				for _, p := range asStrings(g["principals"]) {
					if dbxBroadGroups[strings.ToLower(strings.TrimPrefix(p, "groups/"))] && strings.HasPrefix(p, "groups/") {
						hits = append(hits, Hit{Path: fmt.Sprintf("grant_rules.%d", i), Msg: fmt.Sprintf("%s is granted to %s, so any user can act as or administer this principal and gain its privileges.", role, p)})
					}
				}
			}
			return hits
		})},
	{ID: "TG-DBX-TOK-001", Title: "Personal access token is long-lived", Severity: Medium, Category: CatSecurity, CWE: "CWE-613",
		Types:       []string{"databricks_token", "databricks_obo_token"},
		Remediation: "Set lifetime_seconds to 90 days or less and rotate with time_rotating; prefer OAuth for service principals.",
		Check: managed(func(r *Resource) []Hit {
			v := r.get("lifetime_seconds")
			n, ok := asFloat(v)
			switch {
			case isUnknown(v):
			case v == nil || ok && n == 0:
				return []Hit{{Path: "lifetime_seconds", Msg: "No lifetime_seconds: the token gets the workspace maximum (up to 730 days) or, where no maximum is set, never expires."}}
			case ok && n > 90*dbxDay:
				return []Hit{{Path: "lifetime_seconds", Sev: Low, Msg: fmt.Sprintf("The token lives %.0f days; a leaked token stays usable that long.", n/dbxDay)}}
			}
			return nil
		})},
	{ID: "TG-DBX-WS-001", Title: "Workspace configuration weakens a security control", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"databricks_workspace_conf"},
		Remediation: `Keep enableIpAccessLists "true", leave the deprecated global and cluster-named init scripts disabled, keep verbose audit logs on and set maxTokenLifetimeDays to 90 or less.`,
		Check: managed(func(r *Resource) []Hit {
			conf, _ := r.Attrs["custom_config"].(map[string]any)
			str := func(k string) string { s := fmt.Sprint(conf[k]); return strings.ToLower(strings.TrimSpace(s)) }
			var hits []Hit
			add := func(sev Severity, msg string) { hits = append(hits, Hit{Path: "custom_config", Sev: sev, Msg: msg}) }
			if str("enableIpAccessLists") == "false" {
				add(Low, "enableIpAccessLists is false, so no IP access list is enforced and the workspace accepts logins and API calls from any address.")
			}
			for _, k := range []string{"enableDeprecatedGlobalInitScripts", "enableDeprecatedClusterNamedInitScripts"} {
				if str(k) == "true" {
					add(Medium, k+" is true, which re-enables legacy init scripts stored in DBFS, where workspace users can change code that runs as root on clusters.")
				}
			}
			if str("enableVerboseAuditLogs") == "false" {
				add(Low, "enableVerboseAuditLogs is false, so the commands users run in notebooks are not audited.")
			}
			if n, ok := asFloat(conf["maxTokenLifetimeDays"]); ok && n > 90 {
				add(Low, fmt.Sprintf("maxTokenLifetimeDays is %g, so new personal access tokens can live that many days.", n))
			}
			return hits
		})},
	{ID: "TG-DBX-NET-001", Title: "IP access list allows every address", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"databricks_ip_access_list"},
		Remediation: "List only your offices, VPN egress and CI addresses in ALLOW lists.",
		Check: managed(func(r *Resource) []Hit {
			if t, _ := asString(r.get("list_type")); t != "ALLOW" || is(r.get("enabled"), false) {
				return nil
			}
			for _, ip := range asStrings(r.get("ip_addresses")) {
				if ip == "0.0.0.0/0" || ip == "::/0" {
					return []Hit{{Path: "ip_addresses", Msg: ip + " is in the allow list, so the workspace accepts connections from the whole internet and the list protects nothing."}}
				}
			}
			return nil
		})},
	{ID: "TG-DBX-SEC-001", Title: "Secret value is written in the code", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types:       []string{"databricks_secret"},
		Remediation: "Pass string_value from a sensitive variable fed by CI or a secrets manager, or from a generated value such as random_password; never commit it.",
		Check: managed(func(r *Resource) []Hit {
			if dbxLiteralSecret(r.get("string_value")) {
				return []Hit{{Path: "string_value", Msg: "string_value is a literal, so the secret is in the repository and readable by everyone who can read the code."}}
			}
			return nil
		})},
	{ID: "TG-DBX-SEC-002", Title: "All users can manage or write a secret scope", Severity: Medium, Category: CatSecurity, CWE: "CWE-732",
		Types:       []string{"databricks_secret_scope", "databricks_secret_acl"},
		Remediation: "Omit initial_manage_principal (the creator gets MANAGE) and grant READ to the groups that need the secrets; keep WRITE and MANAGE for admins.",
		Check: managed(func(r *Resource) []Hit {
			if r.Type == "databricks_secret_scope" {
				if p, _ := asString(r.get("initial_manage_principal")); p == "users" {
					return []Hit{{Path: "initial_manage_principal", Msg: `initial_manage_principal = "users" gives every workspace user MANAGE on the scope: they can read, change and delete all its secrets and its ACLs.`}}
				}
				return nil
			}
			p, _ := asString(r.get("principal"))
			perm, _ := asString(r.get("permission"))
			if dbxBroadGroups[strings.ToLower(p)] && (perm == "MANAGE" || perm == "WRITE") {
				return []Hit{{Path: "permission", Msg: fmt.Sprintf("%s on the scope is given to %q, so every user can replace the secrets that jobs and clusters read.", perm, p)}}
			}
			return nil
		})},
	{ID: "TG-DBX-ACC-001", Title: "Workspace does not use customer-managed keys", Severity: Low, Category: CatSecurity, CWE: "CWE-311",
		Types:       []string{"databricks_mws_workspaces"},
		Remediation: "Create databricks_mws_customer_managed_keys and set managed_services_customer_managed_key_id and storage_customer_managed_key_id (Enterprise tier).",
		Check: managed(func(r *Resource) []Hit {
			for _, k := range []string{"managed_services_customer_managed_key_id", "storage_customer_managed_key_id", "customer_managed_key_id"} {
				if r.get(k) != nil {
					return nil
				}
			}
			return []Hit{{Path: "workspace_name", Msg: "Notebooks, secrets and workspace storage are encrypted only with Databricks-managed keys, so you cannot revoke access to them by disabling your own key."}}
		})},
	{ID: "TG-DBX-ACC-002", Title: "Workspace has no private access settings", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types:       []string{"databricks_mws_workspaces"},
		Remediation: "Attach a databricks_mws_private_access_settings (with PrivateLink or Private Service Connect endpoints) through private_access_settings_id, or at least enforce IP access lists.",
		Check: managed(func(r *Resource) []Hit {
			if r.get("private_access_settings_id") == nil {
				return []Hit{{Path: "workspace_name", Msg: "No private_access_settings_id, so the workspace UI and REST API are reached only over the public internet and private connectivity cannot be enforced."}}
			}
			return nil
		})},
	{ID: "TG-DBX-JOB-001", Title: "Job or pipeline runs as a user", Severity: Low, Category: CatBestPrac,
		Types:       []string{"databricks_job", "databricks_pipeline"},
		Remediation: "Set run_as { service_principal_name = \"<application id>\" } so production runs do not depend on, or act with the full rights of, one person.",
		Check: managed(func(r *Resource) []Hit {
			if u, _ := asString(r.get("run_as.user_name")); u != "" {
				return []Hit{{Path: "run_as", Msg: "run_as is the user " + u + ": runs use that person's privileges and break when the user leaves or is disabled."}}
			}
			return nil
		})},
	{ID: "TG-VAL-025", Title: "Value the Databricks provider rejects", Severity: High, Category: CatValidate, CWE: "CWE-20", Blocking: true,
		Types: valueTypes(databricksValueChecks), Remediation: "Use one of the values the Databricks provider accepts; terraform validate and plan fail otherwise.",
		Check: func(r *Resource) []Hit {
			return checkCloudValues(r, databricksValueChecks, "the databricks provider rejects it at plan time")
		}},
}

func init() {
	// Themes for rules whose CWE is not in cweThemes.
	ruleThemes["TG-DBX-UC-002"] = []string{"access", "secrets"}
	ruleThemes["TG-DBX-TOK-001"] = []string{"access", "secrets"}
	ruleThemes["TG-DBX-JOB-001"] = []string{"access"}
}

// databricksValueChecks are the validation.StringInSlice enums of the
// terraform-provider-databricks SDKv2 schema. data_security_mode and
// spot_instance_policy are not listed: the provider does not validate them
// (the API does, at apply time).
var databricksValueChecks = map[string][]awsValueCheck{
	"databricks_cluster": {{attr: "runtime_engine", enum: []string{"PHOTON", "STANDARD"}}},
	"databricks_sql_endpoint": {
		{attr: "cluster_size", enum: []string{"2X-Small", "X-Small", "Small", "Medium", "Large", "X-Large", "2X-Large", "3X-Large", "4X-Large", "5X-Large"}},
		{attr: "warehouse_type", enum: []string{"PRO", "CLASSIC", "REALTIME"}},
	},
	"databricks_pipeline": {{attr: "channel", enum: []string{"current", "preview"}}, {attr: "edition", enum: []string{"pro", "core", "advanced"}}},
	"databricks_job": {
		{attr: "schedule.pause_status", enum: []string{"PAUSED", "UNPAUSED"}},
		{attr: "trigger.pause_status", enum: []string{"PAUSED", "UNPAUSED"}},
		{attr: "continuous.pause_status", enum: []string{"PAUSED", "UNPAUSED"}},
		{attr: "trigger.periodic.unit", enum: []string{"DAYS", "HOURS", "WEEKS"}},
		{attr: "trigger.table_update.condition", enum: []string{"ANY_UPDATED", "ALL_UPDATED"}},
	},
	"databricks_instance_pool": {
		{attr: "aws_attributes.availability", enum: []string{"ON_DEMAND", "SPOT"}},
		{attr: "azure_attributes.availability", enum: []string{"SPOT_AZURE", "ON_DEMAND_AZURE"}},
		{attr: "gcp_attributes.gcp_availability", enum: []string{"ON_DEMAND_GCP", "PREEMPTIBLE_GCP", "PREEMPTIBLE_WITH_FALLBACK_GCP"}},
		{attr: "disk_spec.disk_type.azure_disk_volume_type", enum: []string{"PREMIUM_LRS", "STANDARD_LRS"}},
		{attr: "disk_spec.disk_type.ebs_volume_type", enum: []string{"GENERAL_PURPOSE_SSD", "THROUGHPUT_OPTIMIZED_HDD"}},
	},
	"databricks_ip_access_list": {{attr: "list_type", enum: []string{"ALLOW", "BLOCK"}}},
	"databricks_volume":         {{attr: "volume_type", enum: []string{"MANAGED", "EXTERNAL"}}},
	"databricks_catalog":        {{attr: "enable_predictive_optimization", enum: []string{"DISABLE", "ENABLE", "INHERIT"}}},
	"databricks_schema":         {{attr: "enable_predictive_optimization", enum: []string{"DISABLE", "ENABLE", "INHERIT"}}},
	"databricks_metastore":      {{attr: "delta_sharing_scope", enum: []string{"INTERNAL", "INTERNAL_AND_EXTERNAL"}}},
	"databricks_recipient":      {{attr: "authentication_type", enum: []string{"TOKEN", "DATABRICKS"}}},
	"databricks_query":          {{attr: "run_as_mode", enum: []string{"VIEWER", "OWNER"}}},
}
