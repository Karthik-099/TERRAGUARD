# forbid: TG-K8S-001, TG-K8S-002, TG-K8S-003, TG-HELM-001
resource "kubernetes_deployment_v1" "app" {
  spec {
    template {
      spec {
        container {
          name  = "app"
          image = "ghcr.io/acme/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
          }
        }
      }
    }
  }
}
resource "kubernetes_service_v1" "lb" {
  spec {
    type                        = "LoadBalancer"
    load_balancer_source_ranges = ["203.0.113.0/24"]
  }
}
resource "helm_release" "ingress" {
  chart   = "ingress-nginx"
  version = "4.11.3"
}
