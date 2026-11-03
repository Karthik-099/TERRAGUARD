package engine

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Rules for CloudFormation and SAM templates and Serverless Framework files
// whose logic is more than one setting on one resource type.

var (
	cfnTLS12PolicyRE = regexp.MustCompile(`^ELBSecurityPolicy-(TLS-1-2|TLS13-1-[23]|FS-1-2)-`)
	cfnPointerRE     = regexp.MustCompile(`(?i)_(NAME|ARN|ID|PATH|KEY_ID)$`) // names a secret rather than holding it
	cfnSecretKeyRE   = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
	cfnIAMTypes      = []string{"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group",
		"AWS::IAM::RolePolicy", "AWS::IAM::UserPolicy", "AWS::IAM::GroupPolicy"}
	cfnLambdaTypes = []string{"AWS::Lambda::Function", "AWS::Serverless::Function"}
)

func cfnRule(id string, sev Severity, cat, cwe string, types []string, title, remedy string, check func(r *Resource) []Hit) Rule {
	return Rule{ID: id, Title: title, Severity: sev, Category: cat, CWE: cwe, Types: types, Remediation: remedy, Check: check}
}

func cfnHit(path, msg string) []Hit { return []Hit{{Path: path, Msg: msg}} }

// cfnProp reads a value under Properties.
func cfnProp(r *Resource, p string) any { return r.get("Properties." + p) }

func cfnPropStr(r *Resource, p string) string { s, _ := asString(cfnProp(r, p)); return s }

// cfnUnset is an absent or empty value; Unknown counts as set.
func cfnUnset(v any) bool { return empty(v) }

// cfnList returns the maps in a list, and false when the list itself is not known.
func cfnList(v any) ([]map[string]any, bool) {
	if isUnknown(v) {
		return nil, false
	}
	var out []map[string]any
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
	case map[string]any:
		out = append(out, t)
	}
	return out, true
}

// cfnKeyValue finds an entry with key field kf equal to key in a list of
// key/value maps (load balancer attributes, cluster settings, parameters).
func cfnKeyValue(v any, kf, key, vf string) (val any, unknown bool) {
	list, ok := cfnList(v)
	if !ok {
		return nil, true
	}
	for _, m := range list {
		if isUnknown(m[kf]) {
			return nil, true
		}
		if k, _ := asString(m[kf]); k == key {
			return m[vf], isUnknown(m[vf])
		}
	}
	return nil, false
}

// cfnRetention fires when a backup retention (default 1 day) is under 7 days.
func cfnRetention(r *Resource) []Hit {
	v := cfnProp(r, "BackupRetentionPeriod")
	if isUnknown(v) {
		return nil
	}
	days := 1.0
	if n, ok := asFloat(v); ok {
		days = n
	} else if v != nil {
		return nil
	}
	if days < 7 {
		return cfnHit("Properties.BackupRetentionPeriod", fmt.Sprintf("Automated backups are kept for %g day(s), so older restore points are lost.", days))
	}
	return nil
}

// cfnLogExports fires unless one of the wanted log types is exported.
func cfnLogExports(r *Resource, want ...string) []Hit {
	v := cfnProp(r, "EnableCloudwatchLogsExports")
	if isUnknown(v) || containsUnknown(v) || contains(asStrings(v), want...) {
		return nil
	}
	return cfnHit("Properties.EnableCloudwatchLogsExports", "No "+strings.Join(want, " or ")+" log is exported to CloudWatch, so activity is not recorded.")
}

// cfnPolicies lists the IAM policy documents a resource holds, with their paths.
func cfnPolicies(r *Resource) (paths []string, docs []any) {
	if r.Type == "serverless_function" {
		if l, ok := r.get("iamRoleStatements").([]any); ok {
			return []string{"iamRoleStatements"}, []any{map[string]any{"Statement": l}}
		}
		return nil, nil
	}
	if d := cfnProp(r, "PolicyDocument"); d != nil {
		paths, docs = append(paths, "Properties.PolicyDocument"), append(docs, d)
	}
	list, _ := cfnList(cfnProp(r, "Policies"))
	for i, p := range list {
		if d := p["PolicyDocument"]; d != nil {
			paths, docs = append(paths, fmt.Sprintf("Properties.Policies.%d.PolicyDocument", i)), append(docs, d)
		}
	}
	return paths, docs
}

// cfnAllow is an Allow statement (Effect defaults to Allow); an unknown Effect is skipped.
func cfnAllow(st map[string]any) bool {
	e, ok := st["Effect"].(string)
	return ok && e == "Allow" || st["Effect"] == nil
}

func cfnStarAction(r *Resource) []Hit {
	paths, docs := cfnPolicies(r)
	for i, d := range docs {
		for _, st := range awspStmts(d) {
			if !cfnAllow(st) || !contains(asStrings(st["Action"]), "*", "*:*") {
				continue
			}
			if contains(asStrings(st["Resource"]), "*") {
				return []Hit{{Path: paths[i], Sev: Critical, Msg: `The policy allows Action "*" on Resource "*", which is full administrator access.`}}
			}
			return cfnHit(paths[i], `The policy allows every action ("*") on the listed resources.`)
		}
	}
	return nil
}

func cfnActionHits(r *Resource, list []string, what string) []Hit {
	paths, docs := cfnPolicies(r)
	for i, d := range docs {
		for _, st := range awspStmts(d) {
			if !cfnAllow(st) || !contains(asStrings(st["Resource"]), "*") {
				continue
			}
			for _, a := range asStrings(st["Action"]) {
				for _, want := range list {
					if ok, _ := awspMatch(a, want); ok {
						return cfnHit(paths[i], fmt.Sprintf("%s on all resources %s.", a, what))
					}
				}
			}
		}
	}
	return nil
}

// cfnOpenIngress reports ingress rules open to the internet that include port.
func cfnOpenIngress(r *Resource, port float64, what string) []Hit {
	var rules []map[string]any
	var paths []string
	if r.Type == "AWS::EC2::SecurityGroupIngress" {
		if p, ok := r.get("Properties").(map[string]any); ok {
			rules, paths = []map[string]any{p}, []string{"Properties"}
		}
	} else {
		list, _ := cfnList(cfnProp(r, "SecurityGroupIngress"))
		for i, m := range list {
			rules, paths = append(rules, m), append(paths, fmt.Sprintf("Properties.SecurityGroupIngress.%d", i))
		}
	}
	for i, m := range rules {
		v4, _ := asString(m["CidrIp"])
		v6, _ := asString(m["CidrIpv6"])
		if v4 != "0.0.0.0/0" && v6 != "::/0" {
			continue
		}
		proto := strings.ToLower(scalar(m["IpProtocol"]))
		if isUnknown(m["IpProtocol"]) || proto == "icmp" || proto == "1" || proto == "icmpv6" || proto == "58" {
			continue
		}
		open := proto == "-1" || proto == "all"
		if !open {
			lo, ok1 := asFloat(m["FromPort"])
			hi, ok2 := asFloat(m["ToPort"])
			open = ok1 && ok2 && (lo == -1 && hi == -1 || lo <= port && port <= hi)
		}
		if open {
			return cfnHit(paths[i], fmt.Sprintf("Anyone on the internet can reach %s (port %g).", what, port))
		}
	}
	return nil
}

func cfnHasSecret(s string) bool {
	if awspAWSKeyRE.MatchString(s) || awspAWSSecretRE.MatchString(s) {
		return true
	}
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s)); err == nil {
		d := string(b)
		return awspAWSKeyRE.MatchString(d) || awspAWSSecretRE.MatchString(d)
	}
	return false
}

// cfnEnvSecret: a variable holding an AWS key, or a secret-named variable with a literal value.
func cfnEnvSecret(vars map[string]any) string {
	for k, v := range vars {
		s, ok := v.(string)
		if !ok || strings.HasPrefix(s, "{{resolve:") || strings.HasPrefix(s, "arn:") {
			continue
		}
		named := secretNameRE.MatchString(k) && !cfnPointerRE.MatchString(k) && len(s) >= 8 && !strings.Contains(s, "${")
		if awspAWSKeyRE.MatchString(s) || awspAWSSecretRE.MatchString(s) || named {
			return k
		}
	}
	return ""
}

var cfnRules = []Rule{
	// Load balancing
	cfnRule("TG-CFN-ELB-201", Low, CatSecurity, "CWE-444", []string{"AWS::ElasticLoadBalancingV2::LoadBalancer"},
		"Application load balancer forwards invalid HTTP headers", "Add the attribute routing.http.drop_invalid_header_fields.enabled = true.",
		func(r *Resource) []Hit {
			if t := cfnProp(r, "Type"); isUnknown(t) || t != nil && t != "application" {
				return nil
			}
			v, unk := cfnKeyValue(cfnProp(r, "LoadBalancerAttributes"), "Key", "routing.http.drop_invalid_header_fields.enabled", "Value")
			if unk || is(v, true) {
				return nil
			}
			return cfnHit("Properties.LoadBalancerAttributes", "Malformed headers reach the targets, which helps request smuggling attacks.")
		}),
	cfnRule("TG-CFN-ELB-202", Medium, CatSecurity, "CWE-319", []string{"AWS::ElasticLoadBalancingV2::Listener"},
		"Load balancer listener serves plain HTTP", "Use Protocol HTTPS, or make the default action a redirect to HTTPS.",
		func(r *Resource) []Hit {
			if cfnPropStr(r, "Protocol") != "HTTP" {
				return nil
			}
			actions, ok := cfnList(cfnProp(r, "DefaultActions"))
			if !ok {
				return nil
			}
			for _, a := range actions {
				if isUnknown(a["Type"]) || isUnknown(get(a, "RedirectConfig.Protocol")) {
					return nil
				}
				if p, _ := asString(get(a, "RedirectConfig.Protocol")); a["Type"] == "redirect" && p == "HTTPS" {
					return nil
				}
			}
			return cfnHit("Properties.Protocol", "Traffic between clients and the load balancer is not encrypted.")
		}),
	cfnRule("TG-CFN-ELB-203", Medium, CatSecurity, "CWE-327", []string{"AWS::ElasticLoadBalancingV2::Listener"},
		"Load balancer listener allows TLS below 1.2", "Set SslPolicy to ELBSecurityPolicy-TLS13-1-2-2021-06 or another TLS 1.2+ policy.",
		func(r *Resource) []Hit {
			if p := cfnPropStr(r, "Protocol"); p != "HTTPS" && p != "TLS" {
				return nil
			}
			v := cfnProp(r, "SslPolicy")
			if isUnknown(v) {
				return nil
			}
			if s, _ := asString(v); s == "" {
				return cfnHit("Properties.Protocol", "No SslPolicy is set, so the default policy accepts TLS 1.0 and 1.1.")
			} else if !cfnTLS12PolicyRE.MatchString(s) {
				return cfnHit("Properties.SslPolicy", "Policy "+s+" accepts protocols older than TLS 1.2.")
			}
			return nil
		}),
	cfnRule("TG-CFN-ELB-204", Low, CatSecurity, "CWE-778", []string{"AWS::ElasticLoadBalancingV2::LoadBalancer"},
		"Load balancer has no access logging", "Add the attribute access_logs.s3.enabled = true with a bucket.",
		func(r *Resource) []Hit {
			if t, _ := asString(cfnProp(r, "Type")); t == "gateway" {
				return nil
			}
			v, unk := cfnKeyValue(cfnProp(r, "LoadBalancerAttributes"), "Key", "access_logs.s3.enabled", "Value")
			if unk || is(v, true) {
				return nil
			}
			return cfnHit("Properties.LoadBalancerAttributes", "Requests through the load balancer are not recorded, so abuse cannot be traced.")
		}),

	// API Gateway
	cfnRule("TG-CFN-APIGATEWAY-201", Medium, CatSecurity, "CWE-306", []string{"AWS::ApiGateway::Method"},
		"API method is open without authorization", "Set AuthorizationType (AWS_IAM, COGNITO_USER_POOLS or CUSTOM), or require an API key.",
		func(r *Resource) []Hit {
			m, auth := cfnProp(r, "HttpMethod"), cfnProp(r, "AuthorizationType")
			if isUnknown(m) || isUnknown(auth) || m == "OPTIONS" || auth != nil && auth != "NONE" || !notTrue(cfnProp(r, "ApiKeyRequired")) {
				return nil
			}
			return cfnHit("Properties.AuthorizationType", "Anyone who can reach the API can call the backend behind this method.")
		}),

	// RDS
	cfnRule("TG-CFN-RDS-201", Medium, CatSecurity, "CWE-311", []string{"AWS::RDS::DBCluster"},
		"RDS cluster storage is not encrypted", "Set StorageEncrypted: true.",
		func(r *Resource) []Hit {
			if cfnProp(r, "SnapshotIdentifier") != nil || cfnProp(r, "SourceDBClusterIdentifier") != nil || !notTrue(cfnProp(r, "StorageEncrypted")) {
				return nil
			}
			return cfnHit("Properties.StorageEncrypted", "Database files, backups and snapshots are stored unencrypted.")
		}),
	cfnRule("TG-CFN-RDS-202", Medium, CatSecurity, "CWE-311", []string{"AWS::RDS::DBInstance"},
		"RDS instance storage is not encrypted", "Set StorageEncrypted: true.",
		func(r *Resource) []Hit {
			e := cfnProp(r, "Engine")
			if s, _ := asString(e); isUnknown(e) || strings.Contains(s, "aurora") {
				return nil
			}
			for _, k := range []string{"DBClusterIdentifier", "SourceDBInstanceIdentifier", "DBSnapshotIdentifier"} {
				if cfnProp(r, k) != nil {
					return nil
				}
			}
			if notTrue(cfnProp(r, "StorageEncrypted")) {
				return cfnHit("Properties.StorageEncrypted", "Database files, backups and snapshots are stored unencrypted.")
			}
			return nil
		}),
	cfnRule("TG-CFN-RDS-203", Info, CatBestPrac, "CWE-778", []string{"AWS::RDS::DBInstance"},
		"RDS instance has no enhanced monitoring", "Set MonitoringInterval to 1, 5, 10, 15, 30 or 60 with a MonitoringRoleArn.",
		func(r *Resource) []Hit {
			v := cfnProp(r, "MonitoringInterval")
			if n, _ := asFloat(v); isUnknown(v) || contains([]string{"1", "5", "10", "15", "30", "60"}, fmt.Sprint(n)) {
				return nil
			}
			return cfnHit("Properties.MonitoringInterval", "Operating system metrics for the instance are not collected.")
		}),
	cfnRule("TG-CFN-RDS-204", Medium, CatSecurity, "CWE-287", []string{"AWS::RDS::DBInstance"},
		"RDS instance does not use IAM database authentication", "Set EnableIAMDatabaseAuthentication: true.",
		func(r *Resource) []Hit {
			if e := cfnPropStr(r, "Engine"); (e == "mysql" || e == "postgres") && notTrue(cfnProp(r, "EnableIAMDatabaseAuthentication")) {
				return cfnHit("Properties.EnableIAMDatabaseAuthentication", "Access relies only on static database passwords instead of short-lived IAM tokens.")
			}
			return nil
		}),
	cfnRule("TG-CFN-RDS-205", Low, CatReliability, "CWE-693", []string{"AWS::RDS::DBInstance"},
		"RDS instance runs in a single availability zone", "Set MultiAZ: true.",
		func(r *Resource) []Hit {
			e := cfnProp(r, "Engine")
			if s, _ := asString(e); isUnknown(e) || s == "" || strings.Contains(s, "aurora") || cfnProp(r, "DBClusterIdentifier") != nil {
				return nil
			}
			if notTrue(cfnProp(r, "MultiAZ")) {
				return cfnHit("Properties.MultiAZ", "An availability zone outage takes the database offline until it is restored.")
			}
			return nil
		}),

	// CloudFront
	cfnRule("TG-CFN-CLOUDFRONT-201", Medium, CatSecurity, "CWE-319", []string{"AWS::CloudFront::Distribution"},
		"CloudFront distribution allows plain HTTP", "Set ViewerProtocolPolicy to redirect-to-https or https-only on every cache behavior.",
		func(r *Resource) []Hit {
			if cfnPropStr(r, "DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy") == "allow-all" {
				return cfnHit("Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy", "Viewers can fetch content over unencrypted HTTP.")
			}
			list, _ := cfnList(cfnProp(r, "DistributionConfig.CacheBehaviors"))
			for i, b := range list {
				if b["ViewerProtocolPolicy"] == "allow-all" {
					return cfnHit(fmt.Sprintf("Properties.DistributionConfig.CacheBehaviors.%d.ViewerProtocolPolicy", i), "Viewers can fetch content over unencrypted HTTP.")
				}
			}
			return nil
		}),
	cfnRule("TG-CFN-CLOUDFRONT-202", Medium, CatSecurity, "CWE-327", []string{"AWS::CloudFront::Distribution"},
		"CloudFront viewers can use TLS below 1.2", "Use your own certificate with MinimumProtocolVersion TLSv1.2_2021.",
		func(r *Resource) []Hit {
			dc := cfnProp(r, "DistributionConfig")
			vc := get(dc, "ViewerCertificate")
			if isUnknown(dc) || isUnknown(vc) {
				return nil
			}
			if vc == nil || is(get(vc, "CloudFrontDefaultCertificate"), true) {
				return []Hit{{Path: "Properties.DistributionConfig", Sev: Low, Msg: "The default *.cloudfront.net certificate accepts TLS 1.0 and 1.1."}}
			}
			v := get(vc, "MinimumProtocolVersion")
			if s, _ := asString(v); !isUnknown(v) && !awspTLS12RE.MatchString(s) {
				return cfnHit("Properties.DistributionConfig.ViewerCertificate", "Viewers can negotiate protocols older than TLS 1.2.")
			}
			return nil
		}),

	// CloudWatch Logs
	cfnRule("TG-CFN-LOGS-201", Low, CatSecurity, "CWE-311", []string{"AWS::Logs::LogGroup"},
		"Log group has no customer managed KMS key", "Set KmsKeyId to a KMS key ARN.",
		func(r *Resource) []Hit {
			if cfnUnset(cfnProp(r, "KmsKeyId")) {
				return cfnHit("Properties", "Log data is encrypted only with a key AWS manages, which you cannot restrict or revoke.")
			}
			return nil
		}),
	cfnRule("TG-CFN-LOGS-202", Low, CatBestPrac, "CWE-779", []string{"AWS::Logs::LogGroup"},
		"Log group keeps logs forever", "Set RetentionInDays.",
		func(r *Resource) []Hit {
			if cfnUnset(cfnProp(r, "RetentionInDays")) {
				return cfnHit("Properties", "Logs never expire, so storage cost grows and old sensitive data is kept.")
			}
			return nil
		}),

	// CodeBuild
	cfnRule("TG-CFN-CODEBUILD-201", Medium, CatSecurity, "CWE-311", []string{"AWS::CodeBuild::Project"},
		"CodeBuild project stores artifacts unencrypted", "Remove EncryptionDisabled from Artifacts.",
		func(r *Resource) []Hit {
			if cfnPropStr(r, "Artifacts.Type") == "S3" && is(cfnProp(r, "Artifacts.EncryptionDisabled"), true) {
				return cfnHit("Properties.Artifacts.EncryptionDisabled", "Build output is written to S3 without encryption.")
			}
			return nil
		}),

	// Lambda
	cfnRule("TG-CFN-LAMBDA-201", High, CatValidate, "CWE-1104", cfnLambdaTypes,
		"Lambda runtime is deprecated", "Move to a supported runtime (python3.12+, nodejs20.x+, java21, dotnet8, provided.al2023).",
		func(r *Resource) []Hit {
			rt := cfnPropStr(r, "Runtime")
			switch {
			case blockedRuntimes[rt]:
				return cfnHit("Properties.Runtime", fmt.Sprintf("Runtime %q is past end of support; AWS blocks creating and updating functions that use it, so the deploy fails.", rt))
			case deprecatedRuntimes[rt]:
				return []Hit{{Path: "Properties.Runtime", Sev: Medium, Msg: fmt.Sprintf("Runtime %q is deprecated: no security patches, and creates and updates will soon be blocked.", rt)}}
			}
			return nil
		}),
	cfnRule("TG-CFN-LAMBDA-202", Low, CatReliability, "CWE-693", cfnLambdaTypes,
		"Lambda function has no dead-letter queue", "Set DeadLetterConfig.TargetArn (SAM: DeadLetterQueue) to an SQS queue or SNS topic.",
		func(r *Resource) []Hit {
			p := "DeadLetterConfig.TargetArn"
			if r.Type == "AWS::Serverless::Function" {
				p = "DeadLetterQueue.TargetArn"
			}
			if cfnUnset(cfnProp(r, p)) {
				return cfnHit("Properties", "Events from failed asynchronous invocations are dropped after the retries.")
			}
			return nil
		}),
	cfnRule("TG-CFN-LAMBDA-203", High, CatSecurity, "CWE-798", cfnLambdaTypes,
		"Lambda environment holds a hard-coded secret", "Read secrets from Secrets Manager or SSM at runtime.",
		func(r *Resource) []Hit {
			vars, _ := cfnProp(r, "Environment.Variables").(map[string]any)
			if k := cfnEnvSecret(vars); k != "" {
				return cfnHit("Properties.Environment.Variables."+k, "Variable "+k+" is visible to anyone who can read the function configuration.")
			}
			return nil
		}),
	cfnRule("TG-CFN-LAMBDA-204", Low, CatSecurity, "CWE-311", cfnLambdaTypes,
		"Lambda environment variables have no customer managed KMS key", "Set KmsKeyArn to a KMS key ARN.",
		func(r *Resource) []Hit {
			vars := cfnProp(r, "Environment.Variables")
			if m, ok := vars.(map[string]any); ok && len(m) > 0 && cfnUnset(cfnProp(r, "KmsKeyArn")) {
				return cfnHit("Properties.Environment", "Variables are encrypted only with a key AWS manages, which you cannot restrict or revoke.")
			}
			return nil
		}),
	cfnRule("TG-CFN-LAMBDA-205", Medium, CatSecurity, "CWE-441", []string{"AWS::Lambda::Permission"},
		"Lambda permission for an AWS service has no source condition", "Set SourceArn or SourceAccount.",
		func(r *Resource) []Hit {
			p := cfnPropStr(r, "Principal")
			if !strings.HasSuffix(p, ".amazonaws.com") || cfnProp(r, "SourceArn") != nil || cfnProp(r, "SourceAccount") != nil {
				return nil
			}
			return cfnHit("Properties.Principal", "Resources in any account using "+p+" can invoke the function (confused deputy).")
		}),

	// DocumentDB
	cfnRule("TG-CFN-DOCDB-201", Low, CatReliability, "CWE-693", []string{"AWS::DocDB::DBCluster"},
		"DocumentDB cluster keeps backups under 7 days", "Set BackupRetentionPeriod to 7 or more.", cfnRetention),
	cfnRule("TG-CFN-DOCDB-202", Low, CatSecurity, "CWE-778", []string{"AWS::DocDB::DBCluster"},
		"DocumentDB cluster exports no logs", `Set EnableCloudwatchLogsExports: [audit, profiler].`,
		func(r *Resource) []Hit { return cfnLogExports(r, "audit", "profiler") }),

	// DynamoDB
	cfnRule("TG-CFN-DYNAMODB-201", Low, CatSecurity, "CWE-311", []string{"AWS::DynamoDB::Table"},
		"DynamoDB table has no customer managed KMS key", "Set SSESpecification with SSEEnabled: true, SSEType: KMS and KMSMasterKeyId.",
		func(r *Resource) []Hit {
			en, key := cfnProp(r, "SSESpecification.SSEEnabled"), cfnProp(r, "SSESpecification.KMSMasterKeyId")
			if isUnknown(en) || is(en, true) && !cfnUnset(key) {
				return nil
			}
			return cfnHit("Properties", "Table data is encrypted only with a key AWS owns, which you cannot restrict, audit or revoke.")
		}),

	// EC2
	cfnRule("TG-CFN-EC2-201", High, CatSecurity, "CWE-798", []string{"AWS::EC2::Instance", "AWS::EC2::LaunchTemplate", "AWS::AutoScaling::LaunchConfiguration"},
		"User data contains AWS credentials", "Use an instance profile instead of keys in user data.",
		func(r *Resource) []Hit {
			for _, p := range []string{"Properties.UserData", "Properties.LaunchTemplateData.UserData"} {
				v := r.get(p)
				s, ok := awspText(v)
				if u, isU := v.(Unknown); isU {
					s, ok = u.Expr, true // !Base64 and !Sub keep their literal text
				}
				if ok && cfnHasSecret(s) {
					return cfnHit(p, "Anyone who can describe the instance, or reach the metadata service, can read these keys.")
				}
			}
			return nil
		}),
	cfnRule("TG-CFN-EC2-202", Medium, CatSecurity, "CWE-284", []string{"AWS::EC2::Instance", "AWS::EC2::LaunchTemplate"},
		"EC2 network interface gets a public IP", "Set AssociatePublicIpAddress: false and reach the instance through a load balancer or bastion.",
		func(r *Resource) []Hit {
			for _, p := range []string{"NetworkInterfaces", "LaunchTemplateData.NetworkInterfaces"} {
				list, _ := cfnList(cfnProp(r, p))
				for i, n := range list {
					if is(n["AssociatePublicIpAddress"], true) {
						return cfnHit(fmt.Sprintf("Properties.%s.%d", p, i), "The instance is directly addressable from the internet.")
					}
				}
			}
			return nil
		}),
	cfnRule("TG-CFN-EC2-203", Medium, CatSecurity, "CWE-918", []string{"AWS::EC2::LaunchTemplate"},
		"Launch template allows IMDSv1", "Set LaunchTemplateData.MetadataOptions.HttpTokens: required.",
		func(r *Resource) []Hit {
			mo := cfnProp(r, "LaunchTemplateData.MetadataOptions")
			t := get(mo, "HttpTokens")
			if isUnknown(mo) || isUnknown(t) || get(mo, "HttpEndpoint") == "disabled" || t == "required" {
				return nil
			}
			return cfnHit("Properties.LaunchTemplateData", "Server-side request forgery can read instance credentials through the metadata service.")
		}),
	cfnRule("TG-CFN-EC2-204", Medium, CatSecurity, "CWE-311", []string{"AWS::AutoScaling::LaunchConfiguration"},
		"Launch configuration EBS volume is not encrypted", "Set Encrypted: true on every Ebs block device.",
		func(r *Resource) []Hit {
			list, _ := cfnList(cfnProp(r, "BlockDeviceMappings"))
			for i, b := range list {
				ebs, ok := b["Ebs"].(map[string]any)
				if ok && ebs["SnapshotId"] == nil && notTrue(ebs["Encrypted"]) {
					return cfnHit(fmt.Sprintf("Properties.BlockDeviceMappings.%d", i), "Volumes launched from this configuration store data unencrypted.")
				}
			}
			return nil
		}),

	// ECR
	cfnRule("TG-CFN-ECR-201", High, CatSecurity, "CWE-284", []string{"AWS::ECR::Repository"},
		"ECR repository policy lets anyone in", "Name specific principals, or scope the statement with aws:PrincipalOrgID.",
		func(r *Resource) []Hit {
			for _, st := range awspStmts(cfnProp(r, "RepositoryPolicyText")) {
				if awspPublic(st) {
					return cfnHit("Properties.RepositoryPolicyText", "Any AWS account can use this repository.")
				}
			}
			return nil
		}),

	// ECS
	cfnRule("TG-CFN-ECS-201", Low, CatBestPrac, "CWE-778", []string{"AWS::ECS::Cluster"},
		"ECS Container Insights is off", "Add ClusterSettings: [{Name: containerInsights, Value: enabled}].",
		func(r *Resource) []Hit {
			v, unk := cfnKeyValue(cfnProp(r, "ClusterSettings"), "Name", "containerInsights", "Value")
			if unk || v == "enabled" || v == "enhanced" {
				return nil
			}
			return cfnHit("Properties", "Task-level CPU, memory and restart metrics are not collected.")
		}),
	cfnRule("TG-CFN-ECS-202", Medium, CatSecurity, "CWE-319", []string{"AWS::ECS::TaskDefinition"},
		"ECS task mounts EFS without transit encryption", "Set EFSVolumeConfiguration.TransitEncryption: ENABLED.",
		func(r *Resource) []Hit {
			list, _ := cfnList(cfnProp(r, "Volumes"))
			for i, v := range list {
				efs, ok := v["EFSVolumeConfiguration"].(map[string]any)
				if ok && !isUnknown(efs["TransitEncryption"]) && efs["TransitEncryption"] != "ENABLED" {
					return cfnHit(fmt.Sprintf("Properties.Volumes.%d", i), "File data travels between the task and EFS unencrypted.")
				}
			}
			return nil
		}),

	// EKS
	cfnRule("TG-CFN-EKS-201", Medium, CatSecurity, "CWE-284", []string{"AWS::EKS::Nodegroup"},
		"EKS node group allows SSH from anywhere", "Set RemoteAccess.SourceSecurityGroups, or remove RemoteAccess.",
		func(r *Resource) []Hit {
			if !cfnUnset(cfnProp(r, "RemoteAccess.Ec2SshKey")) && cfnUnset(cfnProp(r, "RemoteAccess.SourceSecurityGroups")) {
				return cfnHit("Properties.RemoteAccess", "Without source security groups, port 22 on the nodes is open to 0.0.0.0/0.")
			}
			return nil
		}),
	cfnRule("TG-CFN-EKS-202", Low, CatSecurity, "CWE-311", []string{"AWS::EKS::Cluster"},
		"EKS secrets are not encrypted with your KMS key", "Add EncryptionConfig with Resources: [secrets] and a KMS key.",
		func(r *Resource) []Hit {
			list, ok := cfnList(cfnProp(r, "EncryptionConfig"))
			if !ok {
				return nil
			}
			for _, c := range list {
				if isUnknown(c["Resources"]) || contains(asStrings(c["Resources"]), "secrets") {
					return nil
				}
			}
			return cfnHit("Properties", "Kubernetes secrets are not envelope-encrypted with a key you control.")
		}),

	// ElastiCache
	cfnRule("TG-CFN-ELASTICACHE-201", Medium, CatSecurity, "CWE-306", []string{"AWS::ElastiCache::ReplicationGroup"},
		"ElastiCache replication group requires no authentication", "Enable TransitEncryptionEnabled and set AuthToken or UserGroupIds.",
		func(r *Resource) []Hit {
			if cfnUnset(cfnProp(r, "AuthToken")) && cfnUnset(cfnProp(r, "UserGroupIds")) {
				return cfnHit("Properties", "Any client that reaches the cluster can read and write every key.")
			}
			if notTrue(cfnProp(r, "TransitEncryptionEnabled")) {
				return cfnHit("Properties", "Authentication needs in-transit encryption; without it clients connect without a password check.")
			}
			return nil
		}),

	// OpenSearch
	cfnRule("TG-CFN-ES-201", Low, CatSecurity, "CWE-778", []string{"AWS::Elasticsearch::Domain", "AWS::OpenSearchService::Domain"},
		"Search domain publishes no logs", "Enable at least one LogPublishingOptions entry.",
		func(r *Resource) []Hit {
			v := cfnProp(r, "LogPublishingOptions")
			if isUnknown(v) {
				return nil
			}
			m, _ := v.(map[string]any)
			for _, o := range m {
				if isUnknown(o) || isUnknown(get(o, "Enabled")) || is(get(o, "Enabled"), true) {
					return nil
				}
			}
			return cfnHit("Properties", "Slow queries, errors and access are not recorded.")
		}),

	// Glue
	cfnRule("TG-CFN-GLUE-201", Medium, CatSecurity, "CWE-311", []string{"AWS::Glue::DataCatalogEncryptionSettings"},
		"Glue Data Catalog is not fully encrypted", "Set EncryptionAtRest.CatalogEncryptionMode: SSE-KMS and ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted: true.",
		func(r *Resource) []Hit {
			s := "DataCatalogEncryptionSettings."
			mode, ret := cfnProp(r, s+"EncryptionAtRest.CatalogEncryptionMode"), cfnProp(r, s+"ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted")
			if m, _ := asString(mode); !isUnknown(mode) && !strings.HasPrefix(m, "SSE-KMS") {
				return cfnHit("Properties.DataCatalogEncryptionSettings", "Catalog metadata is stored without KMS encryption.")
			}
			if notTrue(ret) {
				return cfnHit("Properties.DataCatalogEncryptionSettings", "Connection passwords are returned in plain text.")
			}
			return nil
		}),
	cfnRule("TG-CFN-GLUE-202", Low, CatSecurity, "CWE-311", []string{"AWS::Glue::Crawler", "AWS::Glue::DevEndpoint", "AWS::Glue::Job"},
		"Glue component has no security configuration", "Attach a Glue security configuration that encrypts S3, logs and bookmarks.",
		func(r *Resource) []Hit {
			p := "SecurityConfiguration"
			if r.Type == "AWS::Glue::Crawler" {
				p = "CrawlerSecurityConfiguration"
			}
			if cfnUnset(cfnProp(r, p)) {
				return cfnHit("Properties", "Data, logs and job bookmarks written by this component are not encrypted with your key.")
			}
			return nil
		}),
	cfnRule("TG-CFN-GLUE-203", Medium, CatSecurity, "CWE-311", []string{"AWS::Glue::SecurityConfiguration"},
		"Glue security configuration leaves data unencrypted", "Enable CloudWatch, job bookmark and S3 encryption.",
		func(r *Resource) []Hit {
			enc := cfnProp(r, "EncryptionConfiguration")
			if isUnknown(enc) {
				return nil
			}
			var off []string
			for name, p := range map[string]string{"CloudWatch logs": "CloudWatchEncryption.CloudWatchEncryptionMode", "job bookmarks": "JobBookmarksEncryption.JobBookmarksEncryptionMode"} {
				v := get(enc, p)
				if !isUnknown(v) && (v == nil || v == "DISABLED") {
					off = append(off, name)
				}
			}
			s3 := false
			list, ok := cfnList(get(enc, "S3Encryptions"))
			for _, e := range list {
				s3 = s3 || isUnknown(e["S3EncryptionMode"]) || e["S3EncryptionMode"] != nil && e["S3EncryptionMode"] != "DISABLED"
			}
			if ok && !s3 {
				off = append(off, "S3 data")
			}
			if len(off) > 0 {
				sort.Strings(off)
				return cfnHit("Properties.EncryptionConfiguration", "Not encrypted: "+strings.Join(off, ", ")+".")
			}
			return nil
		}),

	// IAM
	cfnRule("TG-CFN-IAM-201", High, CatSecurity, "CWE-269", cfnIAMTypes,
		"IAM policy allows every action", "List the actions the role needs instead of \"*\".", cfnStarAction),
	cfnRule("TG-CFN-IAM-202", High, CatSecurity, "CWE-522", cfnIAMTypes,
		"IAM policy exposes credentials", "Scope credential-issuing actions to specific resource ARNs.",
		func(r *Resource) []Hit {
			return cfnActionHits(r, awspCredActions, "can mint or read credentials for other identities")
		}),
	cfnRule("TG-CFN-IAM-203", Medium, CatSecurity, "CWE-200", cfnIAMTypes,
		"IAM policy allows data exfiltration on all resources", "Scope object, parameter and secret reads to specific resource ARNs.",
		func(r *Resource) []Hit {
			return cfnActionHits(r, awspExfilActions, "reads every object, parameter or secret in the account")
		}),
	cfnRule("TG-CFN-IAM-204", Critical, CatSecurity, "CWE-284", []string{"AWS::IAM::Role"},
		"Role can be assumed by anyone", "Trust specific principals instead of \"*\".",
		func(r *Resource) []Hit {
			for _, st := range awspStmts(cfnProp(r, "AssumeRolePolicyDocument")) {
				if awspPublic(st) {
					return cfnHit("Properties.AssumeRolePolicyDocument", "Any AWS account can assume this role and use its permissions.")
				}
			}
			return nil
		}),
	cfnRule("TG-CFN-IAM-205", Medium, CatSecurity, "CWE-284", []string{"AWS::IAM::Role"},
		"Role trusts an entire AWS account", "Trust specific role ARNs, or require sts:ExternalId or MFA in a Condition.",
		func(r *Resource) []Hit {
			for _, st := range awspStmts(cfnProp(r, "AssumeRolePolicyDocument")) {
				if st["Effect"] == "Deny" || st["Condition"] != nil {
					continue
				}
				for _, p := range awspPrincipals(st, "AWS") {
					if awspAccountRE.MatchString(p) {
						return cfnHit("Properties.AssumeRolePolicyDocument", "Any identity in account "+p+" with sts:AssumeRole permission can assume this role.")
					}
				}
			}
			return nil
		}),

	// KMS
	cfnRule("TG-CFN-KMS-201", High, CatSecurity, "CWE-284", []string{"AWS::KMS::Key"},
		"KMS key policy allows any principal", "Name specific principals, or add a Condition that scopes \"*\".",
		func(r *Resource) []Hit {
			for _, st := range awspStmts(cfnProp(r, "KeyPolicy")) {
				if cfnAllow(st) && st["Condition"] == nil && contains(awspPrincipals(st, "AWS"), "*") {
					return cfnHit("Properties.KeyPolicy", "Any AWS identity can use or manage this key.")
				}
			}
			return nil
		}),
	cfnRule("TG-CFN-KMS-202", Low, CatSecurity, "CWE-320", []string{"AWS::KMS::Key"},
		"KMS key rotation is off", "Set EnableKeyRotation: true.",
		func(r *Resource) []Hit {
			spec := cfnProp(r, "KeySpec")
			if isUnknown(spec) || spec != nil && spec != "SYMMETRIC_DEFAULT" || !notTrue(cfnProp(r, "EnableKeyRotation")) {
				return nil
			}
			return cfnHit("Properties", "The same key material protects data indefinitely, so a leaked key stays useful.")
		}),

	// MQ
	cfnRule("TG-CFN-MQ-201", Low, CatSecurity, "CWE-778", []string{"AWS::AmazonMQ::Broker"},
		"ActiveMQ broker audit logging is off", "Set Logs.Audit: true.",
		func(r *Resource) []Hit {
			e := cfnProp(r, "EngineType")
			if s, _ := asString(e); isUnknown(e) || strings.EqualFold(s, "RabbitMQ") || !notTrue(cfnProp(r, "Logs.Audit")) {
				return nil
			}
			return cfnHit("Properties", "Management actions on the broker are not audited.")
		}),

	// MSK
	cfnRule("TG-CFN-MSK-201", Medium, CatSecurity, "CWE-319", []string{"AWS::MSK::Cluster"},
		"MSK cluster allows plaintext traffic", "Set EncryptionInTransit.ClientBroker: TLS and InCluster: true.",
		func(r *Resource) []Hit {
			if cb, ok := asString(cfnProp(r, "EncryptionInfo.EncryptionInTransit.ClientBroker")); ok && cb != "TLS" {
				return cfnHit("Properties.EncryptionInfo.EncryptionInTransit.ClientBroker", "Clients can send and read messages without encryption.")
			}
			if is(cfnProp(r, "EncryptionInfo.EncryptionInTransit.InCluster"), false) {
				return cfnHit("Properties.EncryptionInfo.EncryptionInTransit.InCluster", "Data between brokers travels unencrypted.")
			}
			return nil
		}),
	cfnRule("TG-CFN-MSK-202", Low, CatSecurity, "CWE-778", []string{"AWS::MSK::Cluster"},
		"MSK cluster has no broker logging", "Enable LoggingInfo.BrokerLogs to CloudWatch Logs, Firehose or S3.",
		func(r *Resource) []Hit {
			for _, k := range []string{"CloudWatchLogs", "Firehose", "S3"} {
				v := cfnProp(r, "LoggingInfo.BrokerLogs."+k+".Enabled")
				if isUnknown(v) || is(v, true) {
					return nil
				}
			}
			if isUnknown(cfnProp(r, "LoggingInfo")) {
				return nil
			}
			return cfnHit("Properties", "Broker errors and access are not recorded.")
		}),

	// Neptune
	cfnRule("TG-CFN-NEPTUNE-201", Low, CatReliability, "CWE-693", []string{"AWS::Neptune::DBCluster"},
		"Neptune cluster keeps backups under 7 days", "Set BackupRetentionPeriod to 7 or more.", cfnRetention),
	cfnRule("TG-CFN-NEPTUNE-202", Low, CatSecurity, "CWE-778", []string{"AWS::Neptune::DBCluster"},
		"Neptune audit logs are not exported", "Set EnableCloudwatchLogsExports: [audit].",
		func(r *Resource) []Hit { return cfnLogExports(r, "audit") }),

	// SSM
	cfnRule("TG-CFN-SSM-201", High, CatSecurity, "CWE-798", []string{"AWS::SSM::Parameter"},
		"Parameter holds a hard-coded secret", "Create the secret outside the template (SecureString or Secrets Manager) and reference it.",
		func(r *Resource) []Hit {
			name, val := cfnPropStr(r, "Name"), cfnPropStr(r, "Value")
			low := strings.ToLower(name + " " + val)
			if !secretNameRE.MatchString(name) || len(val) < 8 || strings.ContainsAny(val, " ") || strings.Contains(val, "${") ||
				strings.Contains(val, "{{") || strings.Contains(low, "test") || strings.Contains(low, "example") {
				return nil
			}
			return cfnHit("Properties.Value", "The value is stored in plain text in the template and in the String parameter.")
		}),

	// QLDB
	cfnRule("TG-CFN-QLDB-201", Medium, CatReliability, "CWE-693", []string{"AWS::QLDB::Ledger"},
		"QLDB ledger deletion protection is off", "Remove DeletionProtection: false.",
		func(r *Resource) []Hit {
			if is(cfnProp(r, "DeletionProtection"), false) {
				return cfnHit("Properties.DeletionProtection", "The ledger and its history can be deleted in one call.")
			}
			return nil
		}),

	// Redshift
	cfnRule("TG-CFN-REDSHIFT-201", Medium, CatSecurity, "CWE-319", []string{"AWS::Redshift::ClusterParameterGroup"},
		"Redshift parameter group does not require SSL", "Add the parameter require_ssl = true.",
		func(r *Resource) []Hit {
			v, unk := cfnKeyValue(cfnProp(r, "Parameters"), "ParameterName", "require_ssl", "ParameterValue")
			if unk || is(v, true) {
				return nil
			}
			return cfnHit("Properties", "Clients can connect without encryption, so queries and results can be read on the network.")
		}),

	// S3
	cfnRule("TG-CFN-S3-201", Medium, CatSecurity, "CWE-284", []string{"AWS::S3::Bucket"},
		"S3 public access block is only partly set", "Set all four PublicAccessBlockConfiguration settings to true.",
		func(r *Resource) []Hit {
			pab, ok := cfnProp(r, "PublicAccessBlockConfiguration").(map[string]any)
			if !ok {
				return nil
			}
			var missing []string
			for _, k := range []string{"BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"} {
				if _, set := pab[k]; !set {
					missing = append(missing, k)
				}
			}
			if len(missing) > 0 {
				return cfnHit("Properties.PublicAccessBlockConfiguration", "Settings left out default to false: "+strings.Join(missing, ", ")+".")
			}
			return nil
		}),
	cfnRule("TG-CFN-S3-202", Medium, CatValidate, "CWE-311", []string{"AWS::S3::Bucket"},
		"S3 bucket encryption algorithm is invalid", "Use SSEAlgorithm AES256, aws:kms or aws:kms:dsse.",
		func(r *Resource) []Hit {
			list, _ := cfnList(cfnProp(r, "BucketEncryption.ServerSideEncryptionConfiguration"))
			for i, c := range list {
				if a, ok := asString(get(c, "ServerSideEncryptionByDefault.SSEAlgorithm")); ok && !contains([]string{"AES256", "aws:kms", "aws:kms:dsse"}, a) {
					return cfnHit(fmt.Sprintf("Properties.BucketEncryption.ServerSideEncryptionConfiguration.%d", i), "S3 rejects algorithm "+a+", so the stack fails to deploy.")
				}
			}
			return nil
		}),

	// SageMaker
	cfnRule("TG-CFN-SAGEMAKER-201", Low, CatSecurity, "CWE-311", []string{"AWS::SageMaker::NotebookInstance", "AWS::SageMaker::Domain"},
		"SageMaker storage has no customer managed KMS key", "Set KmsKeyId to a KMS key ARN.",
		func(r *Resource) []Hit {
			if cfnUnset(cfnProp(r, "KmsKeyId")) {
				return cfnHit("Properties", "Notebook and domain storage is encrypted only with a key AWS manages.")
			}
			return nil
		}),

	// Secrets Manager
	cfnRule("TG-CFN-SECRETS-201", Low, CatSecurity, "CWE-311", []string{"AWS::SecretsManager::Secret"},
		"Secret has no customer managed KMS key", "Set KmsKeyId to a customer managed KMS key.",
		func(r *Resource) []Hit {
			v := cfnProp(r, "KmsKeyId")
			if s, _ := asString(v); cfnUnset(v) || strings.HasPrefix(s, "alias/aws/") || strings.HasPrefix(s, "aws/") {
				return cfnHit("Properties", "The secret is encrypted with the AWS managed key, so key policy cannot limit who decrypts it.")
			}
			return nil
		}),

	// Security groups
	cfnRule("TG-CFN-SG-201", High, CatSecurity, "CWE-284", []string{"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"},
		"Security group opens SSH to the internet", "Limit CidrIp to known ranges or use Session Manager.",
		func(r *Resource) []Hit { return cfnOpenIngress(r, 22, "SSH") }),
	cfnRule("TG-CFN-SG-202", High, CatSecurity, "CWE-284", []string{"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"},
		"Security group opens RDP to the internet", "Limit CidrIp to known ranges or use a bastion.",
		func(r *Resource) []Hit { return cfnOpenIngress(r, 3389, "RDP") }),
	cfnRule("TG-CFN-SG-203", Low, CatSecurity, "CWE-284", []string{"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"},
		"Security group opens HTTP to the internet", "Serve HTTPS through a load balancer, or limit CidrIp.",
		func(r *Resource) []Hit { return cfnOpenIngress(r, 80, "unencrypted HTTP") }),
	cfnRule("TG-CFN-SG-204", Info, CatBestPrac, "CWE-710", []string{"AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"},
		"Security group rule has no description", "Add a Description to every rule.",
		func(r *Resource) []Hit {
			if r.Type != "AWS::EC2::SecurityGroup" {
				if cfnUnset(cfnProp(r, "Description")) {
					return cfnHit("Properties", "Reviewers cannot tell why this rule exists.")
				}
				return nil
			}
			for _, k := range []string{"SecurityGroupIngress", "SecurityGroupEgress"} {
				list, _ := cfnList(cfnProp(r, k))
				for i, m := range list {
					if cfnUnset(m["Description"]) {
						return cfnHit(fmt.Sprintf("Properties.%s.%d", k, i), "Reviewers cannot tell why this rule exists.")
					}
				}
			}
			return nil
		}),

	// WAF
	cfnRule("TG-CFN-WAF-201", Medium, CatSecurity, "CWE-917", []string{"AWS::WAFv2::WebACL"},
		"WAF web ACL does not block Log4Shell", "Add AWSManagedRulesKnownBadInputsRuleSet with OverrideAction None and keep Log4JRCE active.",
		func(r *Resource) []Hit {
			rules, ok := cfnList(cfnProp(r, "Rules"))
			if !ok {
				return nil
			}
			for i, rule := range rules {
				g := get(rule, "Statement.ManagedRuleGroupStatement")
				if n, _ := asString(get(g, "Name")); n != "AWSManagedRulesKnownBadInputsRuleSet" {
					continue
				}
				path := fmt.Sprintf("Properties.Rules.%d", i)
				for _, k := range []string{"ExcludedRules", "RuleActionOverrides"} {
					list, _ := cfnList(get(g, k))
					for _, x := range list {
						if x["Name"] == "Log4JRCE" {
							return cfnHit(path, "The Log4JRCE rule is excluded, so CVE-2021-44228 payloads pass.")
						}
					}
				}
				if oa, ok := rule["OverrideAction"].(map[string]any); ok && oa["None"] == nil {
					return cfnHit(path, "The known-bad-inputs group only counts matches; Log4Shell payloads pass.")
				}
				return nil
			}
			return cfnHit("Properties", "No AWSManagedRulesKnownBadInputsRuleSet rule; Log4Shell (CVE-2021-44228) payloads pass.")
		}),

	// Serverless Framework
	cfnRule("TG-SLS-IAM-201", High, CatSecurity, "CWE-269", []string{"serverless_function"},
		"Function role allows every action", "List the actions the function needs instead of \"*\".", cfnStarAction),
	cfnRule("TG-SLS-LAMBDA-201", High, CatSecurity, "CWE-798", []string{"serverless_function"},
		"Function environment holds AWS credentials", "Use the function's role instead of access keys in environment variables.",
		func(r *Resource) []Hit {
			vars, _ := r.get("environment").(map[string]any)
			for k, v := range vars {
				if s, ok := v.(string); ok && (awspAWSKeyRE.MatchString(s) || cfnSecretKeyRE.MatchString(s) && secretNameRE.MatchString(k)) {
					return cfnHit("environment."+k, "Variable "+k+" is visible to anyone who can read the function configuration.")
				}
			}
			return nil
		}),
}

// cfnRuleIDs maps foreign check IDs to these rules, so existing skip comments keep working.
var cfnRuleIDs = map[string][]string{
	"CKV_AWS_131": {"TG-CFN-ELB-201"}, "CKV_AWS_2": {"TG-CFN-ELB-202"}, "CKV_AWS_103": {"TG-CFN-ELB-203"}, "CKV_AWS_91": {"TG-CFN-ELB-204"},
	"CKV_AWS_59": {"TG-CFN-APIGATEWAY-201"}, "CKV_AWS_96": {"TG-CFN-RDS-201"}, "CKV_AWS_16": {"TG-CFN-RDS-202"},
	"CKV_AWS_118": {"TG-CFN-RDS-203"}, "CKV_AWS_161": {"TG-CFN-RDS-204"}, "CKV_AWS_157": {"TG-CFN-RDS-205"},
	"CKV_AWS_34": {"TG-CFN-CLOUDFRONT-201"}, "CKV_AWS_174": {"TG-CFN-CLOUDFRONT-202"},
	"CKV_AWS_158": {"TG-CFN-LOGS-201"}, "CKV_AWS_66": {"TG-CFN-LOGS-202"}, "CKV_AWS_78": {"TG-CFN-CODEBUILD-201"},
	"CKV_AWS_363": {"TG-CFN-LAMBDA-201"}, "CKV_AWS_116": {"TG-CFN-LAMBDA-202"}, "CKV_AWS_45": {"TG-CFN-LAMBDA-203"},
	"CKV_AWS_173": {"TG-CFN-LAMBDA-204"}, "CKV_AWS_364": {"TG-CFN-LAMBDA-205"},
	"CKV_AWS_360": {"TG-CFN-DOCDB-201"}, "CKV_AWS_85": {"TG-CFN-DOCDB-202"}, "CKV_AWS_119": {"TG-CFN-DYNAMODB-201"},
	"CKV_AWS_46": {"TG-CFN-EC2-201"}, "CKV_AWS_88": {"TG-CFN-EC2-202"}, "CKV_AWS_79": {"TG-CFN-EC2-203"}, "CKV_AWS_8": {"TG-CFN-EC2-204"},
	"CKV_AWS_32": {"TG-CFN-ECR-201"}, "CKV_AWS_65": {"TG-CFN-ECS-201"}, "CKV_AWS_97": {"TG-CFN-ECS-202"},
	"CKV_AWS_100": {"TG-CFN-EKS-201"}, "CKV_AWS_58": {"TG-CFN-EKS-202"}, "CKV_AWS_31": {"TG-CFN-ELASTICACHE-201"},
	"CKV_AWS_84": {"TG-CFN-ES-201"}, "CKV_AWS_94": {"TG-CFN-GLUE-201"}, "CKV_AWS_195": {"TG-CFN-GLUE-202"}, "CKV_AWS_99": {"TG-CFN-GLUE-203"},
	"CKV_AWS_62": {"TG-CFN-IAM-201"}, "CKV_AWS_63": {"TG-CFN-IAM-201"}, "CKV_AWS_107": {"TG-CFN-IAM-202"}, "CKV_AWS_108": {"TG-CFN-IAM-203"},
	"CKV_AWS_60": {"TG-CFN-IAM-204"}, "CKV_AWS_61": {"TG-CFN-IAM-205"}, "CKV_AWS_33": {"TG-CFN-KMS-201"}, "CKV_AWS_7": {"TG-CFN-KMS-202"},
	"CKV_AWS_197": {"TG-CFN-MQ-201"}, "CKV_AWS_81": {"TG-CFN-MSK-201"}, "CKV_AWS_80": {"TG-CFN-MSK-202"},
	"CKV_AWS_361": {"TG-CFN-NEPTUNE-201"}, "CKV_AWS_101": {"TG-CFN-NEPTUNE-202"}, "CKV_AWS_384": {"TG-CFN-SSM-201"},
	"CKV_AWS_172": {"TG-CFN-QLDB-201"}, "CKV_AWS_105": {"TG-CFN-REDSHIFT-201"}, "CKV_AWS_19": {"TG-CFN-S3-202"},
	"CKV_AWS_187": {"TG-CFN-SAGEMAKER-201"}, "CKV_AWS_149": {"TG-CFN-SECRETS-201"},
	"CKV_AWS_24": {"TG-CFN-SG-201"}, "CKV_AWS_25": {"TG-CFN-SG-202"}, "CKV_AWS_260": {"TG-CFN-SG-203"}, "CKV_AWS_23": {"TG-CFN-SG-204"},
	"CKV_AWS_192": {"TG-CFN-WAF-201"},
	"CKV_AWS_1":   {"TG-SLS-IAM-201"}, "CKV_AWS_49": {"TG-SLS-IAM-201"}, "CKV_AWS_41": {"TG-SLS-LAMBDA-201"},
}

func init() {
	for ckv, ids := range cfnRuleIDs {
		foreignRules[ckv] = append(foreignRules[ckv], ids...)
	}
}
