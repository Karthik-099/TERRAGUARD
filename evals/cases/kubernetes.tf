# expect: TG-K8S-001, TG-K8S-002, TG-K8S-003, TG-HELM-001, TG-SEC-001
resource "kubernetes_deployment_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    template {
      metadata {
        labels = { app = "app" }
      }
      spec {
        host_network = true
        container {
          name  = "app"
          image = "nginx:latest"
          security_context {
            privileged = true
          }
        }
      }
    }
  }
}
resource "kubernetes_service_v1" "lb" {
  metadata {
    name = "lb"
  }
  spec {
    type = "LoadBalancer"
  }
}
resource "helm_release" "ingress" {
  name       = "ingress"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
}
resource "kubernetes_secret_v1" "db" {
  metadata {
    name = "db"
  }
  data = { password = "s3cr3t-value" }
}
