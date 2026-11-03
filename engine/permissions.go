package engine

import (
	"encoding/json"
	"sort"
	"strings"
)

// The IAM actions an apply needs to create each resource type. Checked with
// the IAM policy simulator by `preflight --live`, so a missing permission
// fails before apply instead of halfway through.
var awsCreateActions = map[string][]string{
	"aws_instance":                      {"ec2:RunInstances"},
	"aws_launch_template":               {"ec2:CreateLaunchTemplate"},
	"aws_vpc":                           {"ec2:CreateVpc"},
	"aws_subnet":                        {"ec2:CreateSubnet"},
	"aws_security_group":                {"ec2:CreateSecurityGroup"},
	"aws_eip":                           {"ec2:AllocateAddress"},
	"aws_internet_gateway":              {"ec2:CreateInternetGateway"},
	"aws_nat_gateway":                   {"ec2:CreateNatGateway"},
	"aws_route_table":                   {"ec2:CreateRouteTable"},
	"aws_ebs_volume":                    {"ec2:CreateVolume"},
	"aws_lb":                            {"elasticloadbalancing:CreateLoadBalancer"},
	"aws_lb_target_group":               {"elasticloadbalancing:CreateTargetGroup"},
	"aws_lb_listener":                   {"elasticloadbalancing:CreateListener"},
	"aws_db_instance":                   {"rds:CreateDBInstance"},
	"aws_rds_cluster":                   {"rds:CreateDBCluster"},
	"aws_s3_bucket":                     {"s3:CreateBucket"},
	"aws_iam_role":                      {"iam:CreateRole"},
	"aws_iam_policy":                    {"iam:CreatePolicy"},
	"aws_iam_role_policy_attachment":    {"iam:AttachRolePolicy"},
	"aws_lambda_function":               {"lambda:CreateFunction", "iam:PassRole"},
	"aws_ecs_cluster":                   {"ecs:CreateCluster"},
	"aws_ecs_service":                   {"ecs:CreateService"},
	"aws_ecs_task_definition":           {"ecs:RegisterTaskDefinition"},
	"aws_eks_cluster":                   {"eks:CreateCluster", "iam:PassRole"},
	"aws_eks_node_group":                {"eks:CreateNodegroup", "iam:PassRole"},
	"aws_kms_key":                       {"kms:CreateKey"},
	"aws_dynamodb_table":                {"dynamodb:CreateTable"},
	"aws_sqs_queue":                     {"sqs:CreateQueue"},
	"aws_sns_topic":                     {"sns:CreateTopic"},
	"aws_cloudwatch_log_group":          {"logs:CreateLogGroup"},
	"aws_route53_record":                {"route53:ChangeResourceRecordSets"},
	"aws_cloudfront_distribution":       {"cloudfront:CreateDistribution"},
	"aws_ecr_repository":                {"ecr:CreateRepository"},
	"aws_secretsmanager_secret":         {"secretsmanager:CreateSecret"},
	"aws_elasticache_replication_group": {"elasticache:CreateReplicationGroup"},
}

// PermissionNeed is one IAM action the plan's creates require.
type PermissionNeed struct {
	Action    string   `json:"action"`
	Resources []string `json:"resources"`
	Decision  string   `json:"decision"` // allowed, explicitDeny, implicitDeny, unknown
}

// deleteActions are the delete calls that don't follow the Create -> Delete naming.
var deleteActions = map[string]string{
	"ec2:RunInstances":                 "ec2:TerminateInstances",
	"ec2:AllocateAddress":              "ec2:ReleaseAddress",
	"route53:ChangeResourceRecordSets": "route53:ChangeResourceRecordSets",
	"s3:CreateBucket":                  "s3:DeleteBucket",
	"iam:PassRole":                     "",
	"lambda:CreateFunction":            "lambda:DeleteFunction",
	"rds:CreateDBInstance":             "rds:DeleteDBInstance",
}

func deleteAction(create string) string {
	if d, ok := deleteActions[create]; ok {
		return d
	}
	svc, op, _ := strings.Cut(create, ":")
	if rest, ok := strings.CutPrefix(op, "Create"); ok {
		return svc + ":Delete" + rest
	}
	return ""
}

// PermissionNeeds lists the IAM actions needed to create and delete what the
// plan creates, deletes or replaces. Updates are not covered: their API calls
// depend on which attributes change.
func PermissionNeeds(planJSON string) []PermissionNeed {
	var p quotaPlan
	if json.Unmarshal([]byte(planJSON), &p) != nil {
		return nil
	}
	byAction := map[string][]string{}
	for _, rc := range p.ResourceChanges {
		if rc.Mode == "data" {
			continue
		}
		for _, act := range rc.Change.Actions { // a replace is delete plus create
			for _, a := range awsCreateActions[rc.Type] {
				switch act {
				case "create":
					byAction[a] = append(byAction[a], rc.Address)
				case "delete":
					if d := deleteAction(a); d != "" {
						byAction[d] = append(byAction[d], rc.Address)
					}
				}
			}
		}
	}
	out := make([]PermissionNeed, 0, len(byAction))
	for _, a := range sortedKeys(byAction) {
		res := byAction[a]
		sort.Strings(res)
		out = append(out, PermissionNeed{Action: a, Resources: res, Decision: "unknown"})
	}
	return out
}
