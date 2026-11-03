package engine

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Kubernetes manifests are converted to the shape the Terraform kubernetes
// provider uses (snake_case keys, nested objects as single blocks, list
// fields under singular block names), so the provider rules run unchanged.

func init() { formatParsers[FormatKubernetes] = parseKubernetes }

// k8sKindTypes maps a manifest kind to the provider resource type.
var k8sKindTypes = map[string]string{
	"Pod": "kubernetes_pod_v1", "PodTemplate": "kubernetes_pod_v1",
	"Deployment": "kubernetes_deployment_v1", "ReplicaSet": "kubernetes_deployment_v1", "DeploymentConfig": "kubernetes_deployment_v1",
	"DaemonSet": "kubernetes_daemon_set_v1", "StatefulSet": "kubernetes_stateful_set_v1",
	"Job": "kubernetes_job_v1", "CronJob": "kubernetes_cron_job_v1",
	"ReplicationController": "kubernetes_replication_controller_v1",
	"Service":               "kubernetes_service_v1", "Ingress": "kubernetes_ingress_v1",
	"Role": "kubernetes_role_v1", "ClusterRole": "kubernetes_cluster_role_v1",
	"RoleBinding": "kubernetes_role_binding_v1", "ClusterRoleBinding": "kubernetes_cluster_role_binding_v1",
	"ServiceAccount": "kubernetes_service_account_v1", "Namespace": "kubernetes_namespace_v1",
	"NetworkPolicy": "kubernetes_network_policy_v1", "Secret": "kubernetes_secret_v1", "ConfigMap": "kubernetes_config_map_v1",
	"PodSecurityPolicy": "kubernetes_pod_security_policy",
	"PersistentVolume":  "kubernetes_persistent_volume_v1", "PersistentVolumeClaim": "kubernetes_persistent_volume_claim_v1",
	"StorageClass": "kubernetes_storage_class_v1", "PriorityClass": "kubernetes_priority_class_v1",
	"HorizontalPodAutoscaler": "kubernetes_horizontal_pod_autoscaler_v2", "PodDisruptionBudget": "kubernetes_pod_disruption_budget_v1",
	"LimitRange": "kubernetes_limit_range_v1", "ResourceQuota": "kubernetes_resource_quota_v1", "Endpoints": "kubernetes_endpoints_v1",
	"ValidatingWebhookConfiguration": "kubernetes_validating_webhook_configuration_v1",
	"MutatingWebhookConfiguration":   "kubernetes_mutating_webhook_configuration_v1",
	"CertificateSigningRequest":      "kubernetes_certificate_signing_request_v1",
}

// k8sBlockNames renames list fields to the provider's singular block names.
var k8sBlockNames = map[string]string{
	"containers": "container", "initContainers": "init_container", "ephemeralContainers": "ephemeral_container",
	"volumes": "volume", "ports": "port", "volumeMounts": "volume_mount", "envFrom": "env_from",
	"rules": "rule", "subjects": "subject", "tolerations": "toleration", "ranges": "range", "paths": "path",
	"volumeClaimTemplates": "volume_claim_template", "readinessGates": "readiness_gate",
	"topologySpreadConstraints": "topology_spread_constraint", "webhooks": "webhook",
}

// k8sMapFields stay plain maps (provider map attributes), keys untouched.
var k8sMapFields = map[string]bool{
	"labels": true, "annotations": true, "data": true, "stringData": true, "binaryData": true, "nodeSelector": true,
	"limits": true, "requests": true, "matchLabels": true, "parameters": true, "capacity": true, "hard": true,
}

// k8sStringFields are strings in the provider schema though manifests write numbers.
var k8sStringFields = map[string]bool{"run_as_user": true, "run_as_group": true, "fs_group": true}

func parseKubernetes(name, src string) ([]*Resource, []Finding) {
	docs, err := decodeYAMLDocs(src)
	var syntax []Finding
	if err != nil {
		syntax = append(syntax, formatSyntax(name, "Kubernetes", err))
	}
	var out []*Resource
	for i, d := range docs {
		out = append(out, k8sObjects(name, d.value, d.lines, i, "")...)
	}
	return out, syntax
}

// k8sObjects converts one manifest object, or every item of a kind: List.
func k8sObjects(file string, v any, lines map[string]int, doc int, root string) []*Resource {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	kind, _ := m["kind"].(string)
	if kind == "" {
		return nil
	}
	if api, _ := m["apiVersion"].(string); isCrossplaneAPI(api) {
		return crossplaneObjects(file, v, lines, doc, root, "")
	}
	if strings.HasSuffix(kind, "List") && m["items"] != nil {
		items, _ := m["items"].([]any)
		var out []*Resource
		for i, it := range items {
			out = append(out, k8sObjects(file, it, subLines(lines, "items."+strconv.Itoa(i)), doc, join(root, "items."+strconv.Itoa(i)))...)
		}
		return out
	}
	name, _ := asString(get(m, "metadata.name"))
	if name == "" {
		name = "unnamed"
	}
	ns, _ := asString(get(m, "metadata.namespace"))
	if ns == "" {
		ns = "default"
	}
	typ := k8sKindTypes[kind]
	if typ == "" {
		typ = "kubernetes_" + k8sSnake(kind)
	}
	r := &Resource{Address: kind + "." + ns + "." + name, Mode: "managed", Type: typ, Name: name, File: file, Line: k8sFirstLine(lines), Lines: map[string]int{}, Doc: doc, Root: root}
	body := map[string]any{}
	for k, e := range m {
		if k != "apiVersion" && k != "kind" {
			body[k] = e
		}
	}
	r.Attrs = k8sConvMap(body, "", "", lines, r.Lines)
	return []*Resource{r}
}

func k8sFirstLine(lines map[string]int) int {
	first := 0
	for _, l := range lines {
		if first == 0 || l < first {
			first = l
		}
	}
	return first
}

// k8sConvMap converts an object; src and dst are the YAML and provider paths.
func k8sConvMap(m map[string]any, src, dst string, lines, out map[string]int) map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := map[string]any{}
	for _, k := range keys {
		v, sp := m[k], join(src, k)
		nk := k8sBlockNames[k]
		if nk == "" {
			nk = k8sSnake(k)
		}
		dp := join(dst, nk)
		k8sRecord(out, dp, lines[sp])
		switch t := v.(type) {
		case map[string]any:
			if k8sMapFields[k] || k == "selector" && t["matchLabels"] == nil && t["matchExpressions"] == nil {
				for mk, mv := range t {
					k8sRecord(out, dp+"."+mk, lines[sp+"."+mk])
					t[mk] = k8sScalar(mv)
				}
				res[nk] = t
				continue
			}
			k8sRecord(out, dp+".0", lines[sp])
			res[nk] = []any{k8sConvMap(t, sp, dp+".0", lines, out)}
		case []any:
			l := make([]any, len(t))
			for i, e := range t {
				ip, dip := sp+"."+strconv.Itoa(i), dp+"."+strconv.Itoa(i)
				k8sRecord(out, dip, lines[ip])
				if em, ok := e.(map[string]any); ok {
					l[i] = k8sConvMap(em, ip, dip, lines, out)
				} else {
					l[i] = k8sScalar(e)
				}
			}
			res[nk] = l
		default:
			v = k8sScalar(v)
			if f, ok := v.(float64); ok && k8sStringFields[nk] {
				v = strconv.FormatFloat(f, 'f', -1, 64)
			}
			res[nk] = v
		}
	}
	return res
}

// k8sScalar treats template placeholders as values decided at deploy time.
func k8sScalar(v any) any {
	if s, ok := v.(string); ok && strings.Contains(s, "{{") {
		return Unknown{Expr: s}
	}
	return v
}

func k8sRecord(out map[string]int, p string, line int) {
	if line == 0 {
		return
	}
	if _, ok := out[p]; !ok {
		out[p] = line
	}
	if s := stripIndexes(p); s != p {
		if _, ok := out[s]; !ok {
			out[s] = line
		}
	}
}

// k8sSnake turns camelCase into snake_case, keeping acronyms together (hostPID -> host_pid).
func k8sSnake(s string) string {
	s = strings.NewReplacer("IPs", "Ips", "CIDRs", "Cidrs").Replace(s)
	r := []rune(s)
	var b strings.Builder
	for i, c := range r {
		if unicode.IsUpper(c) {
			if i > 0 && (unicode.IsLower(r[i-1]) || unicode.IsDigit(r[i-1]) || i+1 < len(r) && unicode.IsUpper(r[i-1]) && unicode.IsLower(r[i+1])) {
				b.WriteByte('_')
			}
			c = unicode.ToLower(c)
		}
		b.WriteRune(c)
	}
	return b.String()
}
