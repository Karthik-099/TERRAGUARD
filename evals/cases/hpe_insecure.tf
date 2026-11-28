# expect: TG-HPE-STATE-001, TG-HPE-SEC-001, TG-HPE-TLS-001, TG-HPE-TLS-002, TG-HPE-IAM-001, TG-HPE-IAM-002, TG-HPE-NET-001, TG-HPE-LB-001, TG-HPE-LB-002, TG-VAL-026
# forbid: TG-SEC-001
terraform {
  required_version = ">= 1.11"
  required_providers {
    hpe = {
      source  = "HPE/hpe"
      version = "2.3.0"
    }
  }
}

variable "domain_password" {
  type      = string
  sensitive = true
}

resource "hpe_morpheus_network_domain" "corp" {
  name            = "corp.example.com"
  domain_username = "svc-join"
  domain_password = var.domain_password
}

resource "hpe_morpheus_cypher_secret" "api" {
  key   = "api/key"
  value = "Zr7Lp4Wn8Xk2v9QmTq3"
}

resource "hpe_morpheus_network_pool_server" "ipam" {
  name                = "ipam"
  type_code           = "infoblox"
  service_url         = "http://infoblox.corp.internal/wapi/v2.12"
  service_username    = "admin"
  service_password_wo = var.domain_password
  ignore_ssl          = true
}

resource "hpe_morpheus_identity_source_active_directory" "ad" {
  tenant_id               = 1
  name                    = "ad"
  ad_server               = "dc01.corp.internal"
  domain                  = "corp.internal"
  binding_username        = "svc-bind"
  binding_password        = var.domain_password
  default_account_role_id = 7
}

resource "hpe_morpheus_identity_source_saml" "okta" {
  tenant_id                    = 1
  name                         = "okta"
  login_redirect_url           = "https://idp.example.com/sso"
  default_account_role_id      = 7
  validate_assertion_signature = false
}

resource "hpe_morpheus_security_group_rule" "ssh" {
  security_group_id = 1
  name              = "ssh"
  rule_type         = "customRule"
  protocol          = "tcp"
  direction         = "ingress"
  policy            = "accept"
  port_range        = "22"
  source            = "0.0.0.0/0"
}

resource "hpe_morpheus_load_balancer_virtual_server" "web" {
  load_balancer_id = 1
  vip_name         = "web"
  vip_address      = "10.0.0.4"
  vip_port         = 443
  vip_protocol     = "http"
  pool_id          = 11
}

resource "hpe_morpheus_load_balancer_profile" "legacy" {
  load_balancer_id = 1
  name             = "legacy-tls"
  service_type     = "LBClientSslProfile"
  config_client_ssl = {
    ssl_suite = "HIGH_COMPATIBILITY"
  }
}

resource "hpe_morpheus_cloud_affinity_group" "keep" {
  name          = "keep-apart"
  cloud_id      = 1
  affinity_type = "SEPARATE"
}
