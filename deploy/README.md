# Deploying TerraGuard inside your network

Every option runs the same container (`ghcr.io/karthik-099/terraguard`) as a
private service: the web app, the HTTP API, Prometheus metrics and an
optional AI proxy whose keys stay server-side. None of them create a public
endpoint. Mirror the image into your own registry (ECR, ACR or Artifact
Registry) for fully private pulls.

| Target | Path | Private by | Validated with |
|---|---|---|---|
| AWS | [aws/](aws) | ECS Fargate in private subnets, internal HTTPS load balancer, security groups limited to your CIDRs | `terraform validate`, TerraGuard (grade A) |
| Azure | [azure/](azure) | Container Apps environment with an internal load balancer in your VNet, ingress not exposed externally | `terraform validate`, TerraGuard (grade A) |
| Google Cloud | [gcp/](gcp) | Cloud Run with internal-only ingress and a group-restricted invoker | `terraform validate`, TerraGuard (grade A) |
| Any Kubernetes (EKS, AKS, GKE, on-prem) | [helm/terraguard](helm/terraguard) | ClusterIP service, NetworkPolicy, non-root read-only pods, no service-account token | `helm lint`, `helm template` |

```bash
# AWS
cd deploy/aws && terraform init && terraform apply \
  -var vpc_id=vpc-123 -var 'private_subnet_ids=["subnet-a","subnet-b"]' \
  -var 'allowed_cidrs=["10.0.0.0/8"]' -var certificate_arn=arn:aws:acm:... -var access_logs_bucket=my-alb-logs

# Kubernetes
helm install terraguard deploy/helm/terraguard -n platform --create-namespace \
  --set envFromSecret=terraguard-keys
```

Configure models and policies with environment variables (see
[.env.example](../.env.example)): any OpenAI-compatible endpoint, custom auth
headers, local-only mode, audit log and SSO proxy trust. CI templates for AWS
CodeBuild, Azure Pipelines and Google Cloud Build are in
[templates/](../templates).
