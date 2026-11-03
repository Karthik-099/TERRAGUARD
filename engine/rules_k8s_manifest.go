package engine

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Kubernetes rules for controls the provider rules did not cover: control
// plane flags, seccomp, high UIDs, dashboards, ingress snippets and RBAC
// escalation paths. They read the provider shape, so they run on manifests
// and Terraform alike.

func init() {
	for ckv, ids := range k8sManifestIDs {
		foreignRules[ckv] = append(foreignRules[ckv], ids...)
	}
	for ckv, id := range k8sFlagIDs {
		foreignRules[ckv] = append(foreignRules[ckv], id)
	}
}

// k8sManifestIDs maps foreign check IDs to the rules that cover them.
var k8sManifestIDs = map[string][]string{
	"CKV_K8S_31": {"TG-K8S-POD-401"}, "CKV_K8S_33": {"TG-K8S-POD-402"}, "CKV_K8S_38": {"TG-K8S-012"},
	"CKV_K8S_40": {"TG-K8S-POD-403"}, "CKV_K8S_45": {"TG-K8S-POD-404"}, "CKV_K8S_78": {"TG-K8S-API-430"},
	"CKV_K8S_152": {"TG-K8S-ING-402"}, "CKV_K8S_153": {"TG-K8S-ING-401", "TG-K8S-ING-402", "TG-K8S-ING-403"},
	"CKV_K8S_154": {"TG-K8S-ING-403"},
	"CKV_K8S_155": {"TG-K8S-RBAC-401"}, "CKV_K8S_156": {"TG-K8S-RBAC-402"}, "CKV_K8S_157": {"TG-K8S-RBAC-403"},
	"CKV_K8S_158": {"TG-K8S-RBAC-404"},
}

var (
	k8sRoles        = []string{"kubernetes_role", "kubernetes_role_v1", "kubernetes_cluster_role", "kubernetes_cluster_role_v1"}
	k8sClusterRoles = []string{"kubernetes_cluster_role", "kubernetes_cluster_role_v1"}
	k8sIngresses    = []string{"kubernetes_ingress", "kubernetes_ingress_v1"}
	k8sLuaRE        = regexp.MustCompile(`\blua_|_lua\b|_lua_|\bkubernetes\.io\b`)
	k8sStrongCipher = map[string]bool{
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": true, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": true,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": true, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": true,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305": true, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": true,
		"TLS_RSA_WITH_AES_256_GCM_SHA384": true, "TLS_RSA_WITH_AES_128_GCM_SHA256": true,
	}
)

var k8sManifestRules = []Rule{
	{ID: "TG-K8S-POD-401", Title: "Pod runs without a seccomp profile", Severity: Low, Category: CatSecurity, CWE: "CWE-693",
		Types: k8sWorkloads, Remediation: `Set security_context { seccomp_profile { type = "RuntimeDefault" } } on the pod (seccompProfile.type: RuntimeDefault).`,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				if bad, known := k8sSeccompMissing(r, p, spec); known && bad {
					hits = append(hits, Hit{Path: p, Msg: "Containers can make every system call, which widens the kernel attack surface for a container escape."})
				}
			})
			return hits
		}},
	{ID: "TG-K8S-POD-402", Title: "Kubernetes dashboard is deployed", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: k8sWorkloads, Remediation: "Remove the dashboard, or reach it only through kubectl proxy with a least-privilege service account.",
		Check: func(r *Resource) []Hit {
			var hit []Hit
			walkMaps(r.Attrs, "", func(p string, m map[string]any) {
				img, _ := asString(m["image"])
				app, _ := asString(get(m, "labels.app"))
				k8sApp, _ := asString(get(m, "labels.k8s-app"))
				if len(hit) == 0 && (strings.Contains(img, "kubernetes-dashboard") || strings.Contains(img, "kubernetesui/") || app == "kubernetes-dashboard" || k8sApp == "kubernetes-dashboard") {
					hit = append(hit, Hit{Path: p, Msg: "The dashboard is a common target; with a broad service account it hands out control of the cluster."})
				}
			})
			return hit
		}},
	{ID: "TG-K8S-POD-403", Title: "Container runs with a low UID", Severity: Info, Category: CatSecurity, CWE: "CWE-250",
		Types: k8sWorkloads, Remediation: "Set security_context { run_as_user = 10000 } or higher (runAsUser), or use a user namespace (hostUsers: false).",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				if is(spec["host_users"], false) {
					return
				}
				pod := get(spec, "security_context.run_as_user")
				for i, c := range blocksAt(spec, "container") {
					uid := get(c, "security_context.run_as_user")
					if uid == nil {
						uid = pod
					}
					if isUnknown(uid) {
						continue
					}
					if n, ok := asFloat(uid); !ok || n < 10000 {
						name, _ := asString(c["name"])
						hits = append(hits, Hit{Path: join(p, "container."+strconv.Itoa(i)), Msg: "Container " + name + " shares a UID range with host users, so an escape lands as a real host account."})
					}
				}
			})
			return hits
		}},
	{ID: "TG-K8S-POD-404", Title: "Tiller listens on all interfaces", Severity: Medium, Category: CatSecurity, CWE: "CWE-306",
		Types: k8sWorkloads, Remediation: "Pass --listen=localhost:44134 to Tiller, or remove Tiller and move to Helm 3.",
		Check: func(r *Resource) []Hit {
			tillerPod := false
			walkMaps(r.Attrs, "", func(_ string, m map[string]any) { tillerPod = tillerPod || gcppTillerLabels(get(m, "labels")) })
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				for i, c := range blocksAt(spec, "container") {
					img, _ := asString(c["image"])
					if !tillerPod && !tillerImage(img) || containsUnknown(c["args"]) || isUnknown(c["args"]) {
						continue
					}
					local := false
					for _, a := range asStrings(c["args"]) {
						local = local || strings.Contains(a, "--listen") && (strings.Contains(a, "localhost") || strings.Contains(a, "127.0.0.1"))
					}
					if !local {
						hits = append(hits, Hit{Path: join(p, "container."+strconv.Itoa(i)), Msg: "Any pod in the cluster can reach Tiller's unauthenticated gRPC API and install charts as its service account."})
					}
				}
			})
			return hits
		}},
	{ID: "TG-K8S-API-430", Title: "Admission configuration has no event rate limit", Severity: Low, Category: CatReliability, CWE: "CWE-770",
		Types: []string{"kubernetes_admission_configuration"}, Remediation: "Add an EventRateLimit plugin to plugins and enable it with --enable-admission-plugins.",
		Check: func(r *Resource) []Hit {
			if isUnknown(r.Attrs["plugins"]) {
				return nil
			}
			for _, p := range blocksAt(r.Attrs, "plugins") {
				if n := p["name"]; n == "EventRateLimit" || isUnknown(n) {
					return nil
				}
			}
			return []Hit{{Path: "plugins", Msg: "A flood of events can overload the API server and etcd."}}
		}},
	{ID: "TG-K8S-ING-401", Title: "Ingress uses NGINX configuration snippets", Severity: Medium, Category: CatSecurity, CWE: "CWE-94",
		Types: k8sIngresses, Remediation: "Remove *-snippet annotations and set allow-snippet-annotations to false in the controller.",
		Check: func(r *Resource) []Hit {
			return k8sSnippet(r, func(v string) bool { return !k8sLuaRE.MatchString(v) && !strings.Contains(v, "alias") },
				"Anyone who can create an Ingress can inject raw NGINX configuration into the shared controller.")
		}},
	{ID: "TG-K8S-ING-402", Title: "Ingress snippet runs Lua or reads cluster files", Severity: High, Category: CatSecurity, CWE: "CWE-94",
		Types: k8sIngresses, Remediation: "Remove the snippet annotation; it can read the controller's service account token (CVE-2021-25742).",
		Check: func(r *Resource) []Hit {
			return k8sSnippet(r, k8sLuaRE.MatchString, "The snippet can run code in the ingress controller and read its token, which sees every secret.")
		}},
	{ID: "TG-K8S-ING-403", Title: "Ingress snippet uses an alias directive", Severity: High, Category: CatSecurity, CWE: "CWE-22",
		Types: k8sIngresses, Remediation: "Remove the snippet annotation; alias can serve files from the controller's filesystem (CVE-2021-25742).",
		Check: func(r *Resource) []Hit {
			return k8sSnippet(r, func(v string) bool { return strings.Contains(v, "alias") }, "The snippet can expose the controller's files, including its service account token.")
		}},
	k8sRBACRule("TG-K8S-RBAC-401", "Cluster role can change admission webhooks", k8sClusterRoles,
		"Whoever holds it can intercept or rewrite every object sent to the API server.",
		[][3][]string{{{"admissionregistration.k8s.io"}, {"create", "update", "patch"}, {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}}}),
	k8sRBACRule("TG-K8S-RBAC-402", "Cluster role can approve certificate requests", k8sClusterRoles,
		"Whoever holds it can issue client certificates for any identity, including cluster admins.",
		[][3][]string{{{"certificates.k8s.io"}, {"update", "patch"}, {"certificatesigningrequests/approval"}}, {{"certificates.k8s.io"}, {"approve"}, {"signers"}}}),
	k8sRBACRule("TG-K8S-RBAC-403", "Role can bind roles it does not hold", k8sRoles,
		"Whoever holds it can bind any role, including cluster-admin, to themselves.",
		[][3][]string{{{"rbac.authorization.k8s.io"}, {"bind"}, {"rolebindings", "clusterrolebindings", "roles", "clusterroles"}}}),
	k8sRBACRule("TG-K8S-RBAC-404", "Role can escalate role permissions", k8sRoles,
		"Whoever holds it can add any permission to roles, bypassing RBAC's escalation check.",
		[][3][]string{{{"rbac.authorization.k8s.io"}, {"escalate"}, {"roles", "clusterroles"}}}),
}

// k8sSeccompMissing reports a pod spec with no RuntimeDefault or Localhost profile;
// known is false when an unknown value decides it.
func k8sSeccompMissing(r *Resource, p string, spec map[string]any) (bad, known bool) {
	good := func(v any) (ok, set, unk bool) {
		s, _ := asString(v)
		return s == "RuntimeDefault" || s == "Localhost", v != nil, isUnknown(v)
	}
	if ok, set, unk := good(get(spec, "security_context.seccomp_profile.type")); unk {
		return false, false
	} else if set {
		return !ok, true
	}
	cs := blocksAt(spec, "container")
	all := len(cs) > 0
	for _, c := range cs {
		ok, set, unk := good(get(c, "security_context.seccomp_profile.type"))
		if unk {
			return false, false
		}
		if set && !ok {
			return true, true
		}
		all = all && ok
	}
	if all {
		return false, true
	}
	parent := strings.TrimSuffix(strings.TrimSuffix(p, ".0"), "spec")
	for _, a := range []any{get(r.Attrs, parent+"metadata.annotations"), get(r.Attrs, "metadata.annotations")} {
		if m, ok := a.(map[string]any); ok {
			v := m["seccomp.security.alpha.kubernetes.io/pod"]
			if isUnknown(v) {
				return false, false
			}
			if s, _ := asString(v); strings.Contains(s, "runtime/default") || strings.Contains(s, "docker/default") || strings.HasPrefix(s, "localhost/") {
				return false, true
			}
		}
	}
	return true, true
}

func k8sSnippet(r *Resource, match func(string) bool, msg string) []Hit {
	m, _ := r.get("metadata.annotations").(map[string]any)
	for k, v := range m {
		if s, ok := asString(v); ok && strings.Contains(k, "snippet") && match(s) {
			return []Hit{{Path: "metadata.0.annotations." + k, Msg: msg}}
		}
	}
	return nil
}

// k8sRBACRule fires when the role's rules allow every operation (api groups, verbs, resources).
func k8sRBACRule(id, title string, types []string, why string, ops [][3][]string) Rule {
	return Rule{ID: id, Title: title, Severity: High, Category: CatSecurity, CWE: "CWE-269", Types: types,
		Remediation: "Grant this only to the controllers that need it; remove it from roles bound to people or workloads.",
		Check: func(r *Resource) []Hit {
			rules := r.blocks("rule")
			for _, rl := range rules {
				for _, k := range []string{"api_groups", "verbs", "resources"} {
					if isUnknown(rl[k]) || containsUnknown(rl[k]) {
						return nil
					}
				}
			}
			for _, op := range ops {
				can := false
				for _, rl := range rules {
					can = can || k8sGrants(rl["api_groups"], op[0]) && k8sGrants(rl["verbs"], op[1]) && k8sGrants(rl["resources"], op[2])
				}
				if !can {
					return nil
				}
			}
			if len(rules) == 0 {
				return nil
			}
			return []Hit{{Path: "rule", Msg: why}}
		}}
}

func k8sGrants(v any, want []string) bool {
	for _, g := range asStrings(v) {
		if g == "*" || contains(want, g) {
			return true
		}
		for _, w := range want {
			if sub, ok := strings.CutPrefix(g, "*/"); ok && strings.HasSuffix(w, "/"+sub) {
				return true
			}
		}
	}
	return false
}

// k8sFlags are the --flag=value arguments of a control plane container.
type k8sFlags map[string]string

func (f k8sFlags) has(n string) bool      { _, ok := f[n]; return ok }
func (f k8sFlags) not(n, v string) bool   { return f[n] != v }
func (f k8sFlags) list(n string) []string { return strings.Split(f[n], ",") }
func (f k8sFlags) lacks(n, v string) bool { return !contains(f.list(n), v) }
func (f k8sFlags) holds(n, v string) bool { return f.has(n) && contains(f.list(n), v) }
func (f k8sFlags) below(n string, min float64) bool {
	v, err := strconv.ParseFloat(f[n], 64)
	return err != nil || v < min
}
func (f k8sFlags) weakCiphers(n string) bool {
	if !f.has(n) {
		return false
	}
	for _, c := range f.list(n) {
		if !k8sStrongCipher[strings.TrimSpace(c)] {
			return true
		}
	}
	return false
}

// k8sComponentFlags returns the flags of a container running bin, or nil.
func k8sComponentFlags(c map[string]any, bins []string) k8sFlags {
	args := append([]any{}, k8sList(c["command"])...)
	args = append(args, k8sList(c["args"])...)
	found := false
	f := k8sFlags{}
	for _, a := range args {
		s, ok := a.(string)
		if !ok {
			return nil // an unknown argument could change the answer
		}
		if strings.HasPrefix(s, "--") {
			k, v, _ := strings.Cut(s, "=")
			f[k] = v
		} else if contains(bins, path.Base(s)) {
			found = true
		}
	}
	if !found {
		return nil
	}
	return f
}

func k8sList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case nil:
		return nil
	}
	return []any{v}
}

type k8sFlagRule struct {
	id, title string
	sev       Severity
	cwe       string
	bins      []string
	why, fix  string
	bad       func(f k8sFlags) bool
}

func (k k8sFlagRule) rule() Rule {
	return Rule{ID: k.id, Title: k.title, Severity: k.sev, Category: CatSecurity, CWE: k.cwe, Types: k8sWorkloads, Remediation: k.fix,
		Check: func(r *Resource) []Hit {
			var hits []Hit
			forEachPodSpec(r.Attrs, func(p string, spec map[string]any) {
				for i, c := range blocksAt(spec, "container") {
					if f := k8sComponentFlags(c, k.bins); f != nil && k.bad(f) {
						hits = append(hits, Hit{Path: join(p, "container."+strconv.Itoa(i)), Msg: k.why})
					}
				}
			})
			return hits
		}}
}

var (
	apiserver = []string{"kube-apiserver"}
	kcm       = []string{"kube-controller-manager"}
	scheduler = []string{"kube-scheduler"}
	etcd      = []string{"etcd"}
	kubelet   = []string{"kubelet"}
)

var k8sFlagRules = []k8sFlagRule{
	// kube-apiserver
	{"TG-K8S-API-401", "API server allows anonymous requests", Medium, "CWE-306", apiserver,
		"Unauthenticated requests reach the API as system:anonymous.", "Pass --anonymous-auth=false.",
		func(f k8sFlags) bool { return f.not("--anonymous-auth", "false") }},
	{"TG-K8S-API-402", "API server accepts a basic auth file", High, "CWE-522", apiserver,
		"Static passwords never expire and are sent with every request.", "Remove --basic-auth-file; use certificates or OIDC.",
		func(f k8sFlags) bool { return f.has("--basic-auth-file") }},
	{"TG-K8S-API-403", "API server accepts a static token file", High, "CWE-798", apiserver,
		"Static tokens never expire and can only be revoked by restarting the API server.", "Remove --token-auth-file; use certificates, OIDC or service account tokens.",
		func(f k8sFlags) bool { return f.has("--token-auth-file") }},
	{"TG-K8S-API-404", "API server talks to kubelets over plain HTTP", High, "CWE-319", apiserver,
		"Exec, logs and port-forward traffic to nodes is unencrypted.", "Remove --kubelet-https=false.",
		func(f k8sFlags) bool { return f["--kubelet-https"] == "false" }},
	{"TG-K8S-API-405", "API server has no kubelet client certificate", Medium, "CWE-306", apiserver,
		"Kubelets cannot authenticate the API server, so their API must stay open to it.", "Pass --kubelet-client-certificate and --kubelet-client-key.",
		func(f k8sFlags) bool { return !f.has("--kubelet-client-certificate") || !f.has("--kubelet-client-key") }},
	{"TG-K8S-API-406", "API server does not verify kubelet certificates", Medium, "CWE-295", apiserver,
		"Connections to nodes can be intercepted by anyone on the path.", "Pass --kubelet-certificate-authority.",
		func(f k8sFlags) bool { return !f.has("--kubelet-certificate-authority") }},
	{"TG-K8S-API-407", "API server authorizes every request", Critical, "CWE-862", apiserver,
		"AlwaysAllow lets any authenticated identity do anything.", "Use --authorization-mode=Node,RBAC.",
		func(f k8sFlags) bool { return f.holds("--authorization-mode", "AlwaysAllow") }},
	{"TG-K8S-API-408", "API server does not use Node authorization", Medium, "CWE-863", apiserver,
		"A compromised node can read secrets for pods on other nodes.", "Include Node in --authorization-mode.",
		func(f k8sFlags) bool { return f.lacks("--authorization-mode", "Node") }},
	{"TG-K8S-API-409", "API server does not use RBAC", High, "CWE-863", apiserver,
		"Access cannot be limited with roles and bindings.", "Include RBAC in --authorization-mode.",
		func(f k8sFlags) bool { return f.lacks("--authorization-mode", "RBAC") }},
	{"TG-K8S-API-410", "API server enables the AlwaysAdmit plugin", High, "CWE-284", apiserver,
		"Every request is admitted, bypassing admission policy.", "Remove AlwaysAdmit from --enable-admission-plugins.",
		func(f k8sFlags) bool { return f.holds("--enable-admission-plugins", "AlwaysAdmit") }},
	{"TG-K8S-API-411", "API server does not force image pulls", Low, "CWE-284", apiserver,
		"Pods can use private images already cached on a node without pull credentials.", "Add AlwaysPullImages to --enable-admission-plugins.",
		func(f k8sFlags) bool {
			return f.has("--enable-admission-plugins") && f.lacks("--enable-admission-plugins", "AlwaysPullImages")
		}},
	{"TG-K8S-API-412", "API server disables the ServiceAccount plugin", Medium, "CWE-284", apiserver,
		"Pods are no longer tied to service accounts, so their API access is not controlled.", "Remove ServiceAccount from --disable-admission-plugins.",
		func(f k8sFlags) bool { return f.holds("--disable-admission-plugins", "ServiceAccount") }},
	{"TG-K8S-API-413", "API server disables the NamespaceLifecycle plugin", Medium, "CWE-284", apiserver,
		"Objects can be created in namespaces that are being deleted or do not exist.", "Remove NamespaceLifecycle from --disable-admission-plugins.",
		func(f k8sFlags) bool { return f.holds("--disable-admission-plugins", "NamespaceLifecycle") }},
	{"TG-K8S-API-414", "API server does not restrict what nodes can change", Medium, "CWE-284", apiserver,
		"A compromised kubelet can modify other nodes and pods it does not run.", "Add NodeRestriction to --enable-admission-plugins.",
		func(f k8sFlags) bool { return f.lacks("--enable-admission-plugins", "NodeRestriction") }},
	{"TG-K8S-API-415", "API server has an insecure bind address", High, "CWE-306", apiserver,
		"The insecure port skips authentication and authorization.", "Remove --insecure-bind-address.",
		func(f k8sFlags) bool { return f.has("--insecure-bind-address") }},
	{"TG-K8S-API-416", "API server secure port is disabled", High, "CWE-319", apiserver,
		"Clients cannot reach the API over TLS.", "Remove --secure-port=0.",
		func(f k8sFlags) bool { return f["--secure-port"] == "0" }},
	{"TG-K8S-API-417", "API server profiling is on", Low, "CWE-200", apiserver,
		"Profiling endpoints reveal internals and add load.", "Pass --profiling=false.",
		func(f k8sFlags) bool { return f.not("--profiling", "false") }},
	{"TG-K8S-API-418", "API server has no audit log", Medium, "CWE-778", apiserver,
		"There is no record of who did what in the cluster.", "Pass --audit-log-path and an --audit-policy-file.",
		func(f k8sFlags) bool { return !f.has("--audit-log-path") }},
	{"TG-K8S-API-419", "API server keeps audit logs for under 30 days", Low, "CWE-778", apiserver,
		"Evidence is gone before most incidents are investigated.", "Pass --audit-log-maxage=30 or more.",
		func(f k8sFlags) bool { return f.has("--audit-log-path") && f.below("--audit-log-maxage", 30) }},
	{"TG-K8S-API-420", "API server keeps fewer than 10 audit log files", Low, "CWE-778", apiserver,
		"Old audit records are rotated away quickly.", "Pass --audit-log-maxbackup=10 or more.",
		func(f k8sFlags) bool { return f.has("--audit-log-path") && f.below("--audit-log-maxbackup", 10) }},
	{"TG-K8S-API-421", "API server audit log files are small", Low, "CWE-778", apiserver,
		"Audit records rotate after little activity.", "Pass --audit-log-maxsize=100 or more.",
		func(f k8sFlags) bool { return f.has("--audit-log-path") && f.below("--audit-log-maxsize", 100) }},
	{"TG-K8S-API-422", "API server does not check service account tokens exist", Medium, "CWE-613", apiserver,
		"Tokens of deleted service accounts keep working.", "Remove --service-account-lookup=false.",
		func(f k8sFlags) bool { return f["--service-account-lookup"] == "false" }},
	{"TG-K8S-API-423", "API server has no etcd client certificate", Medium, "CWE-306", apiserver,
		"etcd must accept unauthenticated clients to serve the API server.", "Pass --etcd-certfile and --etcd-keyfile.",
		func(f k8sFlags) bool { return !f.has("--etcd-certfile") || !f.has("--etcd-keyfile") }},
	{"TG-K8S-API-424", "API server has no TLS certificate", Medium, "CWE-319", apiserver,
		"The API server falls back to a self-signed certificate clients cannot verify.", "Pass --tls-cert-file and --tls-private-key-file.",
		func(f k8sFlags) bool {
			return strings.TrimSpace(f["--tls-cert-file"]) == "" || strings.TrimSpace(f["--tls-private-key-file"]) == ""
		}},
	{"TG-K8S-API-425", "API server does not verify etcd", Medium, "CWE-295", apiserver,
		"Cluster state can be read or altered by anyone impersonating etcd.", "Pass --etcd-cafile.",
		func(f k8sFlags) bool { return !f.has("--etcd-cafile") }},
	{"TG-K8S-API-426", "API server does not encrypt secrets at rest", Medium, "CWE-311", apiserver,
		"Secrets are stored in etcd and its backups as plain base64.", "Pass --encryption-provider-config with an aescbc, secretbox or KMS provider.",
		func(f k8sFlags) bool { return !f.has("--encryption-provider-config") }},
	{"TG-K8S-API-427", "API server allows weak TLS ciphers", Medium, "CWE-327", apiserver,
		"Clients can negotiate ciphers without forward secrecy or with known weaknesses.", "List only AEAD ECDHE suites in --tls-cipher-suites.",
		func(f k8sFlags) bool { return f.weakCiphers("--tls-cipher-suites") }},

	// kube-controller-manager and kube-scheduler
	{"TG-K8S-KCM-401", "Controller manager keeps terminated pods without limit", Low, "CWE-770", kcm,
		"Finished pods pile up and slow the API server and etcd.", "Pass --terminated-pod-gc-threshold with a positive value.",
		func(f k8sFlags) bool {
			return f.has("--terminated-pod-gc-threshold") && f.below("--terminated-pod-gc-threshold", 1)
		}},
	{"TG-K8S-KCM-402", "Controller manager profiling is on", Low, "CWE-200", kcm,
		"Profiling endpoints reveal internals and add load.", "Pass --profiling=false.",
		func(f k8sFlags) bool { return f.not("--profiling", "false") }},
	{"TG-K8S-KCM-403", "Controllers share one credential", Medium, "CWE-250", kcm,
		"Every controller acts with the controller manager's full rights.", "Pass --use-service-account-credentials=true.",
		func(f k8sFlags) bool { return f.not("--use-service-account-credentials", "true") }},
	{"TG-K8S-KCM-404", "Controller manager has no service account signing key", Medium, "CWE-321", kcm,
		"Service account tokens cannot be signed with a key you control and rotate.", "Pass --service-account-private-key-file.",
		func(f k8sFlags) bool { return strings.TrimSpace(f["--service-account-private-key-file"]) == "" }},
	{"TG-K8S-KCM-405", "Controller manager has no root CA file", Medium, "CWE-295", kcm,
		"Pods cannot verify the API server's certificate.", "Pass --root-ca-file.",
		func(f k8sFlags) bool { return strings.TrimSpace(f["--root-ca-file"]) == "" }},
	{"TG-K8S-KCM-406", "Kubelet server certificate rotation is off", Medium, "CWE-324", append(append([]string{}, kcm...), kubelet...),
		"Kubelet serving certificates are never renewed and expire or stay valid after compromise.", "Remove RotateKubeletServerCertificate=false from --feature-gates.",
		func(f k8sFlags) bool {
			return strings.Contains(f["--feature-gates"], "RotateKubeletServerCertificate=false")
		}},
	{"TG-K8S-KCM-407", "Controller manager listens on all interfaces", Medium, "CWE-668", kcm,
		"Its metrics and health endpoints are reachable from the network.", "Pass --bind-address=127.0.0.1.",
		func(f k8sFlags) bool { return f.not("--bind-address", "127.0.0.1") }},
	{"TG-K8S-SCHED-401", "Scheduler profiling is on", Low, "CWE-200", scheduler,
		"Profiling endpoints reveal internals and add load.", "Pass --profiling=false.",
		func(f k8sFlags) bool { return f.not("--profiling", "false") }},
	{"TG-K8S-SCHED-402", "Scheduler listens on all interfaces", Medium, "CWE-668", scheduler,
		"Its metrics and health endpoints are reachable from the network.", "Pass --bind-address=127.0.0.1.",
		func(f k8sFlags) bool { return f.not("--bind-address", "127.0.0.1") }},

	// etcd
	{"TG-K8S-ETCD-401", "etcd serves clients without TLS", High, "CWE-319", etcd,
		"All cluster state, including secrets, crosses the network in clear text.", "Pass --cert-file and --key-file.",
		func(f k8sFlags) bool { return !f.has("--cert-file") || !f.has("--key-file") }},
	{"TG-K8S-ETCD-402", "etcd does not require client certificates", High, "CWE-306", etcd,
		"Anyone who reaches etcd can read and change all cluster state.", "Pass --client-cert-auth=true.",
		func(f k8sFlags) bool { return f.not("--client-cert-auth", "true") }},
	{"TG-K8S-ETCD-403", "etcd uses self-signed client certificates", Medium, "CWE-295", etcd,
		"Clients cannot verify they are talking to the real etcd.", "Remove --auto-tls=true and use certificates from your CA.",
		func(f k8sFlags) bool { return f["--auto-tls"] == "true" }},
	{"TG-K8S-ETCD-404", "etcd peers talk without TLS", Medium, "CWE-319", etcd,
		"Replication traffic between members, with all secrets, is unencrypted.", "Pass --peer-cert-file and --peer-key-file.",
		func(f k8sFlags) bool { return !f.has("--peer-cert-file") || !f.has("--peer-key-file") }},
	{"TG-K8S-ETCD-405", "etcd does not authenticate peers", Medium, "CWE-306", etcd,
		"Any host that reaches the peer port can join the cluster and copy its data.", "Pass --peer-client-cert-auth=true.",
		func(f k8sFlags) bool { return f.not("--peer-client-cert-auth", "true") }},

	// kubelet
	{"TG-K8S-KUBELET-401", "Kubelet allows anonymous requests", High, "CWE-306", kubelet,
		"Anyone who reaches the node can call the kubelet API.", "Pass --anonymous-auth=false.",
		func(f k8sFlags) bool { return f.not("--anonymous-auth", "false") }},
	{"TG-K8S-KUBELET-402", "Kubelet authorizes every request", Critical, "CWE-862", kubelet,
		"Any authenticated caller can exec into every pod on the node.", "Pass --authorization-mode=Webhook.",
		func(f k8sFlags) bool { return f.holds("--authorization-mode", "AlwaysAllow") }},
	{"TG-K8S-KUBELET-403", "Kubelet does not verify client certificates", Medium, "CWE-295", kubelet,
		"The kubelet cannot authenticate callers by certificate.", "Pass --client-ca-file.",
		func(f k8sFlags) bool { return strings.TrimSpace(f["--client-ca-file"]) == "" }},
	{"TG-K8S-KUBELET-404", "Kubelet read-only port is open", Medium, "CWE-306", kubelet,
		"Pod and node details are served without authentication.", "Pass --read-only-port=0.",
		func(f k8sFlags) bool { return f.not("--read-only-port", "0") }},
	{"TG-K8S-KUBELET-405", "Kubelet streaming connections never time out", Low, "CWE-400", kubelet,
		"Idle exec and port-forward sessions stay open forever.", "Remove --streaming-connection-idle-timeout=0.",
		func(f k8sFlags) bool { return f["--streaming-connection-idle-timeout"] == "0" }},
	{"TG-K8S-KUBELET-406", "Kubelet can change kernel settings", Low, "CWE-250", kubelet,
		"Pods can run with kernel settings different from the node's hardened defaults.", "Pass --protect-kernel-defaults=true.",
		func(f k8sFlags) bool { return f.not("--protect-kernel-defaults", "true") }},
	{"TG-K8S-KUBELET-407", "Kubelet does not manage iptables", Low, "CWE-693", kubelet,
		"Firewall rules can drift from what pod networking expects.", "Remove --make-iptables-util-chains=false.",
		func(f k8sFlags) bool { return f["--make-iptables-util-chains"] == "false" }},
	{"TG-K8S-KUBELET-408", "Kubelet overrides its hostname", Low, "CWE-295", kubelet,
		"The node name no longer matches its certificate, which breaks TLS verification.", "Remove --hostname-override.",
		func(f k8sFlags) bool { return f.has("--hostname-override") }},
	{"TG-K8S-KUBELET-409", "Kubelet has no TLS certificate", Medium, "CWE-319", kubelet,
		"The kubelet serves its API with a self-signed certificate.", "Pass --tls-cert-file and --tls-private-key-file.",
		func(f k8sFlags) bool { return !f.has("--tls-cert-file") || !f.has("--tls-private-key-file") }},
	{"TG-K8S-KUBELET-410", "Kubelet client certificate rotation is off", Medium, "CWE-324", kubelet,
		"Node credentials are never renewed and stop working when they expire.", "Remove --rotate-certificates=false.",
		func(f k8sFlags) bool { return f["--rotate-certificates"] == "false" }},
	{"TG-K8S-KUBELET-411", "Kubelet allows weak TLS ciphers", Medium, "CWE-327", kubelet,
		"Callers can negotiate ciphers without forward secrecy or with known weaknesses.", "List only AEAD ECDHE suites in --tls-cipher-suites.",
		func(f k8sFlags) bool { return f.weakCiphers("--tls-cipher-suites") }},
}

// k8sFlagIDs maps foreign control plane flag checks to the flag rules.
var k8sFlagIDs = map[string]string{
	"CKV_K8S_68": "TG-K8S-API-401", "CKV_K8S_69": "TG-K8S-API-402", "CKV_K8S_70": "TG-K8S-API-403", "CKV_K8S_71": "TG-K8S-API-404",
	"CKV_K8S_72": "TG-K8S-API-405", "CKV_K8S_73": "TG-K8S-API-406", "CKV_K8S_74": "TG-K8S-API-407", "CKV_K8S_75": "TG-K8S-API-408",
	"CKV_K8S_77": "TG-K8S-API-409", "CKV_K8S_79": "TG-K8S-API-410", "CKV_K8S_80": "TG-K8S-API-411", "CKV_K8S_82": "TG-K8S-API-412",
	"CKV_K8S_83": "TG-K8S-API-413", "CKV_K8S_85": "TG-K8S-API-414", "CKV_K8S_86": "TG-K8S-API-415", "CKV_K8S_89": "TG-K8S-API-416",
	"CKV_K8S_90": "TG-K8S-API-417", "CKV_K8S_91": "TG-K8S-API-418", "CKV_K8S_92": "TG-K8S-API-419", "CKV_K8S_93": "TG-K8S-API-420",
	"CKV_K8S_94": "TG-K8S-API-421", "CKV_K8S_96": "TG-K8S-API-422", "CKV_K8S_99": "TG-K8S-API-423", "CKV_K8S_100": "TG-K8S-API-424",
	"CKV_K8S_102": "TG-K8S-API-425", "CKV_K8S_104": "TG-K8S-API-426", "CKV_K8S_105": "TG-K8S-API-427",
	"CKV_K8S_106": "TG-K8S-KCM-401", "CKV_K8S_107": "TG-K8S-KCM-402", "CKV_K8S_108": "TG-K8S-KCM-403", "CKV_K8S_110": "TG-K8S-KCM-404",
	"CKV_K8S_111": "TG-K8S-KCM-405", "CKV_K8S_112": "TG-K8S-KCM-406", "CKV_K8S_113": "TG-K8S-KCM-407",
	"CKV_K8S_114": "TG-K8S-SCHED-401", "CKV_K8S_115": "TG-K8S-SCHED-402",
	"CKV_K8S_116": "TG-K8S-ETCD-401", "CKV_K8S_117": "TG-K8S-ETCD-402", "CKV_K8S_118": "TG-K8S-ETCD-403", "CKV_K8S_119": "TG-K8S-ETCD-404",
	"CKV_K8S_121": "TG-K8S-ETCD-405",
	"CKV_K8S_138": "TG-K8S-KUBELET-401", "CKV_K8S_139": "TG-K8S-KUBELET-402", "CKV_K8S_140": "TG-K8S-KUBELET-403",
	"CKV_K8S_141": "TG-K8S-KUBELET-404", "CKV_K8S_143": "TG-K8S-KUBELET-405", "CKV_K8S_144": "TG-K8S-KUBELET-406",
	"CKV_K8S_145": "TG-K8S-KUBELET-407", "CKV_K8S_146": "TG-K8S-KUBELET-408", "CKV_K8S_148": "TG-K8S-KUBELET-409",
	"CKV_K8S_149": "TG-K8S-KUBELET-410", "CKV_K8S_151": "TG-K8S-KUBELET-411",
}

// k8sFlagRuleSet turns the control-plane flag checks into rules.
func k8sFlagRuleSet() []Rule {
	out := make([]Rule, 0, len(k8sFlagRules))
	for _, f := range k8sFlagRules {
		out = append(out, f.rule())
	}
	return out
}
