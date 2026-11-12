package engine

import (
	"regexp"
	"strconv"
	"strings"
)

// Red Hat rules: OpenShift manifests (read by the Kubernetes parser, so kinds
// become kubernetes_<snake kind>), ROSA through the rhcs provider, and ARO
// through azurerm. DeploymentConfig maps to kubernetes_deployment_v1, so the
// Kubernetes pod rules already check its pod template.

var (
	ocpRosa = []string{"rhcs_cluster_rosa_classic", "rhcs_cluster_rosa_hcp"}
	ocpARO  = []string{"azurerm_redhat_openshift_cluster"}
	// ocpProdRE spots production-style names; non-prod is excluded separately.
	ocpProdRE    = regexp.MustCompile(`(?i)(^|[^a-z])prod(uction)?([^a-z]|$)`)
	ocpNonProdRE = regexp.MustCompile(`(?i)non-?prod|pre-?prod`)
	// ocpDefaultAuthRoles are bound to system:authenticated by every OpenShift install.
	ocpDefaultAuthRoles = map[string]bool{"basic-user": true, "cluster-status": true, "self-access-reviewer": true}
	ocpURLCredRE        = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s]+:[^/@\s]+@`)
)

// ocpRoute: an OpenShift Route (Knative also has kind Route, without spec.to).
func ocpRoute(r *Resource) bool { return r.get("spec.to") != nil }

var redhatRules = managedOnly([]Rule{
	{ID: "TG-OCP-ROUTE-001", Title: "OpenShift route serves plain HTTP", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"kubernetes_route"}, Remediation: "Add spec.tls with termination: edge, reencrypt or passthrough, and insecureEdgeTerminationPolicy: Redirect.",
		Check: func(r *Resource) []Hit {
			if !ocpRoute(r) || r.get("spec.tls") != nil {
				return nil
			}
			return []Hit{{Path: "spec", Msg: "The route has no TLS, so traffic to " + r.Name + " crosses the network unencrypted."}}
		}},
	{ID: "TG-OCP-ROUTE-002", Title: "OpenShift route allows HTTP next to HTTPS", Severity: Medium, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"kubernetes_route"}, Remediation: "Set spec.tls.insecureEdgeTerminationPolicy to Redirect (or None).",
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("spec.tls.insecure_edge_termination_policy")); ocpRoute(r) && strings.EqualFold(v, "Allow") {
				return []Hit{{Path: "spec.0.tls.0.insecure_edge_termination_policy", Msg: "Clients that use http:// are served in clear text instead of being redirected."}}
			}
			return nil
		}},
	{ID: "TG-OCP-ROUTE-003", Title: "OpenShift route claims a wildcard subdomain", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: []string{"kubernetes_route"}, Remediation: "Set spec.wildcardPolicy to None and list each host the application serves.",
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("spec.wildcard_policy")); ocpRoute(r) && strings.EqualFold(v, "Subdomain") {
				return []Hit{{Path: "spec.0.wildcard_policy", Msg: "Every host under the route's domain reaches this service, including names other teams may expect to own."}}
			}
			return nil
		}},
	{ID: "TG-OCP-SCC-001", Title: "SecurityContextConstraints allow privileged containers", Severity: High, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"kubernetes_security_context_constraints"}, Remediation: "Set allowPrivilegedContainer: false; grant the built-in privileged SCC only to the few service accounts that need it.",
		Check: func(r *Resource) []Hit {
			if is(r.get("allow_privileged_container"), true) {
				return []Hit{{Path: "allow_privileged_container", Msg: "Pods admitted by this SCC can run privileged and take over the node."}}
			}
			return nil
		}},
	{ID: "TG-OCP-SCC-002", Title: "SecurityContextConstraints allow host namespaces", Severity: High, Category: CatSecurity, CWE: "CWE-668",
		Types: []string{"kubernetes_security_context_constraints"}, Remediation: "Set allowHostNetwork, allowHostPID and allowHostIPC to false.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, k := range []string{"allow_host_network", "allow_host_pid", "allow_host_ipc"} {
				if is(r.get(k), true) {
					hits = append(hits, Hit{Path: k, Msg: "Pods admitted by this SCC can join the node's " + strings.ToUpper(strings.TrimPrefix(k, "allow_host_")) + " namespace and see or reach host processes and traffic."})
				}
			}
			return hits
		}},
	{ID: "TG-OCP-SCC-003", Title: "SecurityContextConstraints let pods run as any user", Severity: Medium, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"kubernetes_security_context_constraints"}, Remediation: "Set runAsUser.type to MustRunAsRange (the restricted-v2 default) or MustRunAsNonRoot.",
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("run_as_user.type")); v == "RunAsAny" {
				return []Hit{{Path: "run_as_user", Msg: "RunAsAny admits containers that run as root (UID 0)."}}
			}
			return nil
		}},
	{ID: "TG-OCP-SCC-004", Title: "SecurityContextConstraints allow hostPath or every volume type", Severity: High, Category: CatSecurity, CWE: "CWE-668",
		Types: []string{"kubernetes_security_context_constraints"}, Remediation: "List only the volume types pods need (configMap, secret, emptyDir, persistentVolumeClaim, projected, downwardAPI, ephemeral, csi).",
		Check: func(r *Resource) []Hit {
			for _, v := range asStrings(r.get("volume")) {
				if v == "*" || v == "hostPath" {
					return []Hit{{Path: "volume", Msg: "Volume type " + strconv.Quote(v) + " lets pods mount the node's filesystem."}}
				}
			}
			return nil
		}},
	{ID: "TG-OCP-SCC-005", Title: "SecurityContextConstraints allow every capability", Severity: High, Category: CatSecurity, CWE: "CWE-250",
		Types: []string{"kubernetes_security_context_constraints"}, Remediation: "List only the capabilities pods need in allowedCapabilities, and drop ALL by default (requiredDropCapabilities).",
		Check: func(r *Resource) []Hit {
			if contains(asStrings(r.get("allowed_capabilities")), "*") {
				return []Hit{{Path: "allowed_capabilities", Msg: "Pods can add SYS_ADMIN and other capabilities that escape the container."}}
			}
			return nil
		}},
	{ID: "TG-OCP-DC-001", Title: "DeploymentConfig is deprecated", Severity: Low, Category: CatBestPrac,
		Types: []string{"kubernetes_deployment_v1"}, Remediation: "Move to apps/v1 Deployment; DeploymentConfig is deprecated since OpenShift 4.14.",
		Check: func(r *Resource) []Hit {
			if r.Format == FormatKubernetes && strings.HasPrefix(r.Address, "DeploymentConfig.") {
				return []Hit{{Path: "spec", Msg: "DeploymentConfig gets no new features and will be removed; Deployment covers the same rollouts."}}
			}
			return nil
		}},
	{ID: "TG-OCP-BUILD-001", Title: "Docker build does not pull a fresh base image", Severity: Low, Category: CatSecurity, CWE: "CWE-1104",
		Types: []string{"kubernetes_build_config"}, Remediation: "Set spec.strategy.dockerStrategy.forcePull: true so builds pick up base image fixes.",
		Check: func(r *Resource) []Hit {
			ds := r.get("spec.strategy.docker_strategy")
			if ds == nil {
				return nil
			}
			if fp := get(ds, "force_pull"); notTrue(fp) { // forcePull defaults to false
				return []Hit{{Path: "spec.0.strategy.0.docker_strategy", Msg: "The build reuses a cached base image, which can lack security fixes and differ between nodes."}}
			}
			return nil
		}},
	{ID: "TG-OCP-BUILD-002", Title: "BuildConfig holds a credential inline", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"kubernetes_build_config"}, Remediation: "Put credentials in a Secret and reference it with spec.source.sourceSecret or env valueFrom.secretKeyRef.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if u, _ := asString(r.get("spec.source.git.uri")); ocpURLCredRE.MatchString(u) {
				hits = append(hits, Hit{Path: "spec.0.source.0.git.0.uri", Msg: "The Git URL embeds a user name and password or token."})
			}
			walkMaps(r.get("spec"), "spec", func(p string, m map[string]any) {
				for i, e := range blocksAt(m, "env") {
					name, _ := asString(e["name"])
					if v, ok := asString(e["value"]); ok && v != "" && secretNameRE.MatchString(name) {
						hits = append(hits, Hit{Path: p + ".env." + strconv.Itoa(i), Msg: "Build variable " + name + " has a literal value, readable by anyone who can view the BuildConfig."})
					}
				}
			})
			return hits
		}},
	{ID: "TG-OCP-IS-001", Title: "ImageStream imports from an insecure registry", Severity: Medium, Category: CatSecurity, CWE: "CWE-295",
		Types: []string{"kubernetes_image_stream"}, Remediation: "Remove importPolicy.insecure and the openshift.io/image.insecureRepository annotation; serve the registry over trusted TLS.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			ann, _ := r.get("metadata.annotations").(map[string]any) // keys contain dots, so no get()
			if v, _ := asString(ann["openshift.io/image.insecureRepository"]); v == "true" {
				hits = append(hits, Hit{Path: "metadata", Msg: "Every tag is imported without TLS verification, so images can be swapped in transit."})
			}
			for i, t := range blocksAt(r.get("spec"), "tags") {
				if is(get(t, "import_policy.insecure"), true) {
					name, _ := asString(t["name"])
					hits = append(hits, Hit{Path: "spec.0.tags." + strconv.Itoa(i), Msg: "Tag " + name + " is imported over HTTP or unverified TLS, so the image can be swapped in transit."})
				}
			}
			return hits
		}},
	{ID: "TG-OCP-RBAC-001", Title: "Cluster role bound to every authenticated user", Severity: Medium, Category: CatSecurity, CWE: "CWE-269",
		Types: []string{"kubernetes_cluster_role_binding", "kubernetes_cluster_role_binding_v1"}, Remediation: "Bind the role to named groups or service accounts instead of system:authenticated.",
		Check: func(r *Resource) []Hit {
			role, _ := asString(r.get("role_ref.name"))
			if role == "cluster-admin" || strings.HasPrefix(role, "system:") || ocpDefaultAuthRoles[role] {
				return nil // cluster-admin is TG-K8S-007; system: roles are the platform's own
			}
			groups := asStrings(r.get("group_names")) // legacy authorization.openshift.io binding
			for _, s := range r.blocks("subject") {
				if n, _ := asString(s["name"]); n == "system:authenticated" {
					groups = append(groups, n)
				}
			}
			for _, g := range groups {
				if g == "system:authenticated" || g == "system:unauthenticated" {
					return []Hit{{Path: "subject", Msg: "Every identity in " + g + " gets role " + role + " across the cluster."}}
				}
			}
			return nil
		}},
	{ID: "TG-OCP-OAUTH-001", Title: "OAuth identity provider uses plain HTTP", Severity: High, Category: CatSecurity, CWE: "CWE-319",
		Types: []string{"kubernetes_o_auth"}, Remediation: "Use https:// (or ldaps://) for every identity provider URL and remove insecure: true.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for i, idp := range blocksAt(r.get("spec"), "identity_providers") {
				p := "spec.0.identity_providers." + strconv.Itoa(i)
				name, _ := asString(idp["name"])
				walkMaps(idp, p, func(mp string, m map[string]any) {
					for _, k := range []string{"challenge_url", "login_url", "url", "issuer"} {
						u, _ := asString(m[k])
						if strings.HasPrefix(strings.ToLower(u), "http://") || strings.HasPrefix(strings.ToLower(u), "ldap://") && is(m["insecure"], true) {
							hits = append(hits, Hit{Path: mp, Msg: "Identity provider " + name + " sends credentials or tokens over " + u + " without TLS."})
						}
					}
				})
			}
			return hits
		}},

	// ROSA (terraform-redhat/rhcs)
	{ID: "TG-RHCS-001", Title: "ROSA cluster API and routes are public", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: ocpRosa, Remediation: "Set private = true (with aws_private_link = true on classic) and reach the cluster through your VPC.",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("private")) { // the provider treats an absent private as false
				return []Hit{{Path: "private", Msg: "The API server and default routes are reachable from the internet."}}
			}
			return nil
		}},
	{ID: "TG-RHCS-002", Title: "ROSA classic cluster does not encrypt etcd", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: []string{"rhcs_cluster_rosa_classic"}, Remediation: "Set etcd_encryption = true when creating the cluster (it cannot be changed later).",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("etcd_encryption")) { // OCM default is off
				return []Hit{{Path: "etcd_encryption", Msg: "Secrets and other API objects are stored in etcd without application-level encryption."}}
			}
			return nil
		}},
	{ID: "TG-RHCS-003", Title: "ROSA cluster does not use FIPS cryptography", Severity: Low, Category: CatSecurity, CWE: "CWE-327",
		Types: ocpRosa, Remediation: "Set fips = true when creating clusters that must meet FIPS 140 (FedRAMP, government workloads).",
		Check: func(r *Resource) []Hit {
			if notTrue(r.get("fips")) {
				return []Hit{{Path: "fips", Msg: "The cluster uses non-validated cryptographic modules; FIPS can only be chosen at creation."}}
			}
			return nil
		}},
	{ID: "TG-RHCS-004", Title: "Production ROSA cluster runs in one availability zone", Severity: Low, Category: CatReliability,
		Types: ocpRosa, Remediation: "Set multi_az = true (classic) or list three availability_zones and subnets (HCP).",
		Check: func(r *Resource) []Hit {
			if !rosaProd(r) {
				return nil
			}
			azs := r.get("availability_zones")
			if isUnknown(azs) || containsUnknown(azs) {
				return nil
			}
			n := len(asStrings(azs))
			single := n == 1
			if r.Type == "rhcs_cluster_rosa_classic" {
				single = notTrue(r.get("multi_az")) && n <= 1 // multi_az defaults to false
			}
			if single {
				return []Hit{{Path: "availability_zones", Msg: "An outage in one zone takes the whole production cluster down."}}
			}
			return nil
		}},
	{ID: "TG-RHCS-005", Title: "OpenShift user password is written in the configuration", Severity: High, Category: CatSecurity, CWE: "CWE-798",
		Types: []string{"rhcs_cluster_rosa_classic", "rhcs_cluster_rosa_hcp", "rhcs_identity_provider"}, Remediation: "Pass the password from a sensitive variable or a secrets manager, or omit it to get a generated one.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			if p, ok := asString(r.get("admin_credentials.password")); ok && p != "" {
				hits = append(hits, Hit{Path: "admin_credentials", Msg: "The cluster-admin password is stored in source control and in state."})
			}
			if us, ok := r.get("htpasswd.users").([]any); ok {
				for i, u := range us {
					if p, ok := asString(get(u, "password")); ok && p != "" {
						hits = append(hits, Hit{Path: "htpasswd.users." + strconv.Itoa(i), Msg: "An htpasswd user's password is stored in source control and in state."})
					}
				}
			}
			return hits
		}},
	{ID: "TG-RHCS-006", Title: "ROSA cluster disables user workload monitoring", Severity: Low, Category: CatReliability,
		Types: []string{"rhcs_cluster_rosa_classic"}, Remediation: "Remove disable_workload_monitoring or set it to false.",
		Check: func(r *Resource) []Hit {
			if is(r.get("disable_workload_monitoring"), true) {
				return []Hit{{Path: "disable_workload_monitoring", Msg: "Teams lose the built-in Prometheus for their own projects, so application alerts go missing."}}
			}
			return nil
		}},

	// ARO (azurerm_redhat_openshift_cluster)
	{ID: "TG-AZ-ARO-001", Title: "ARO API server is public", Severity: Medium, Category: CatSecurity, CWE: "CWE-284",
		Types: ocpARO, Remediation: `Set api_server_profile { visibility = "Private" } and reach the API through the virtual network.`,
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("api_server_profile.visibility")); v == "Public" {
				return []Hit{{Path: "api_server_profile.0.visibility", Msg: "The cluster API is reachable from the internet."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ARO-002", Title: "ARO default ingress is public", Severity: Low, Category: CatSecurity, CWE: "CWE-284",
		Types: ocpARO, Remediation: `Set ingress_profile { visibility = "Private" } and publish chosen applications through a gateway.`,
		Check: func(r *Resource) []Hit {
			if v, _ := asString(r.get("ingress_profile.visibility")); v == "Public" {
				return []Hit{{Path: "ingress_profile.0.visibility", Msg: "Every route on the default router, including the console and OAuth, is reachable from the internet."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ARO-003", Title: "ARO cluster does not use FIPS cryptography", Severity: Low, Category: CatSecurity, CWE: "CWE-327",
		Types: ocpARO, Remediation: "Set cluster_profile { fips_enabled = true } when creating clusters that must meet FIPS 140.",
		Check: func(r *Resource) []Hit {
			if isUnknown(r.get("cluster_profile")) {
				return nil
			}
			if notTrue(r.get("cluster_profile.fips_enabled")) { // defaults to false
				return []Hit{{Path: "cluster_profile", Msg: "The cluster uses non-validated cryptographic modules; FIPS can only be chosen at creation."}}
			}
			return nil
		}},
	{ID: "TG-AZ-ARO-004", Title: "ARO nodes do not use encryption at host", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
		Types: ocpARO, Remediation: "Set encryption_at_host_enabled = true in main_profile and worker_profile.",
		Check: func(r *Resource) []Hit {
			var hits []Hit
			for _, b := range []string{"main_profile", "worker_profile"} {
				if v := r.get(b); v != nil && !isUnknown(v) && notTrue(r.get(b+".encryption_at_host_enabled")) { // defaults to false
					hits = append(hits, Hit{Path: b, Msg: "Temporary disks and caches on " + strings.TrimSuffix(b, "_profile") + " nodes are not encrypted."})
				}
			}
			return hits
		}},
})

// managedOnly skips data sources, which read a cluster rather than configure it.
func managedOnly(rs []Rule) []Rule {
	for i := range rs {
		check := rs[i].Check
		rs[i].Check = func(r *Resource) []Hit {
			if r.Mode == "data" {
				return nil
			}
			return check(r)
		}
	}
	return rs
}

// rosaProd guesses a production cluster from its name, domain prefix, tags and properties.
func rosaProd(r *Resource) bool {
	var vals []string
	for _, k := range []string{"name", "domain_prefix"} {
		vals = append(vals, asStrings(r.get(k))...)
	}
	for _, k := range []string{"tags", "properties"} {
		if m, ok := r.get(k).(map[string]any); ok {
			for mk, mv := range m {
				vals = append(vals, mk+"="+strings.Join(asStrings(mv), ","))
			}
		}
	}
	for _, v := range vals {
		if ocpProdRE.MatchString(v) && !ocpNonProdRE.MatchString(v) {
			return true
		}
	}
	return false
}
