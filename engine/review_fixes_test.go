package engine

import "testing"

// Inputs that once produced false findings; each must now stay quiet.
func TestRuleReviewFalsePositives(t *testing.T) {
	cases := []struct {
		name, file, src string
		forbid          []string
	}{
		{"data bind mounts", "docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    volumes:\n      - /var/lib/myapp/pg:/var/lib/postgresql/data\n      - /srv/app/uploads:/uploads\n", []string{"TG-COMPOSE-007"}},
		{"wait-for-port loop", ".github/workflows/ci.yml", "on: push\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: until nc -z 127.0.0.1 5432; do sleep 1; done\n", []string{"TG-GHA-004"}},
		{"image name containing tiller", "d.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: { name: a }\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n          image: artilleryio/artillery:2.0.1\n", []string{"TG-K8S-POD-218", "TG-K8S-POD-404"}},
		{"replication group member", "main.tf", "resource \"aws_elasticache_cluster\" \"m\" {\n  cluster_id           = \"m1\"\n  replication_group_id = \"rg\"\n}\n", []string{"TG-AWS-CACHE-202"}},
		{"ICMP from anywhere", "main.tf", "resource \"yandex_vpc_security_group\" \"s\" {\n  ingress {\n    protocol       = \"ICMP\"\n    v4_cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n", []string{"TG-YC-SG-201"}},
		{"gateway TLS from a variable", "main.tf", "resource \"azurerm_application_gateway\" \"g\" {\n  ssl_policy {\n    policy_type          = \"Custom\"\n    min_protocol_version = var.tls\n  }\n}\n", []string{"TG-AZ-AGW-201"}},
		{"gateway with the default policy", "main.tf", "resource \"azurerm_application_gateway\" \"g\" {\n  name = \"g\"\n}\n", []string{"TG-AZ-AGW-201"}},
		{"CA certificate", "Dockerfile", "FROM alpine:3.20\nCOPY corp-ca.pem /usr/local/share/ca-certificates/corp-ca.crt\n", []string{"TG-DOCKER-COPY-004"}},
		{"RabbitMQ in capitals", "main.tf", "resource \"aws_mq_broker\" \"b\" {\n  engine_type = \"RABBITMQ\"\n}\n", []string{"TG-AWS-MQ-201"}},
		{"OIDC sub from a variable", "main.tf", "resource \"aws_iam_role\" \"r\" {\n  assume_role_policy = <<EOF\n{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Principal\":{\"Federated\":\"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com\"},\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"repo:${var.repo}:*\"}}}]}\nEOF\n}\n", []string{"TG-AWS-IAM-206"}},
	}
	for _, c := range cases {
		got := ids(Scan(Input{Files: map[string]string{c.file: c.src}}))
		for _, id := range c.forbid {
			if got[id] > 0 {
				t.Errorf("%s: %s fired", c.name, id)
			}
		}
	}
}

func TestComposePortKeepsIPv6HostAddress(t *testing.T) {
	if ip, host, ctr := csPort("[::1]:8080:80"); ip != "::1" || host != "8080" || ctr != "80" {
		t.Errorf("got %q %q %q", ip, host, ctr)
	}
	if ip, host, ctr := csPort("127.0.0.1:8080:80"); ip != "127.0.0.1" || host != "8080" || ctr != "80" {
		t.Errorf("got %q %q %q", ip, host, ctr)
	}
}
