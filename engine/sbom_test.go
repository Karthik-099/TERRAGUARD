package engine

import (
	"encoding/json"
	"testing"
)

func TestSBOMComponents(t *testing.T) {
	files := map[string]string{
		"main.tf": `terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random" }
  }
}
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}
module "gh" {
  source = "git::https://github.com/Org/Repo.git//sub?ref=v1.2.0"
}
module "local" {
  source = "./modules/x"
}
`,
		".terraform.lock.hcl": `provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = ["h1:abc"]
}
`,
		"Dockerfile": "FROM golang:1.22 AS build\nFROM build AS test\nFROM gcr.io/distroless/static@sha256:abc123\n",
		"k8s.yaml": `apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - name: c
      image: ghcr.io/org/app:2.0
`,
		".gitlab-ci.yml": "image:\n  name: node:20\nbuild:\n  script: [make]\n",
	}
	want := map[string]string{
		"pkg:terraform/hashicorp/aws@5.31.0":                                 "terraform-provider",
		"pkg:terraform/hashicorp/random":                                     "terraform-provider",
		"pkg:terraform/terraform-aws-modules/vpc/aws@5.1.2":                  "terraform-module",
		"pkg:github/org/repo@v1.2.0":                                         "terraform-module",
		"pkg:docker/golang@1.22":                                             "container-image",
		"pkg:docker/distroless/static@sha256%3Aabc123?repository_url=gcr.io": "container-image",
		"pkg:docker/org/app@2.0?repository_url=ghcr.io":                      "container-image",
		"pkg:docker/node@20":                                                 "container-image",
	}
	comps := SBOMComponents(files)
	got := map[string]string{}
	for _, c := range comps {
		got[c.PURL] = c.Kind
		if c.Name == "./modules/x" || c.Name == "build" {
			t.Errorf("local module or stage listed: %+v", c)
		}
	}
	for purl, kind := range want {
		if got[purl] != kind {
			t.Errorf("missing %s (%s); got %v", purl, kind, got)
		}
	}
	b, err := CycloneDX(comps, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Ref  string `json:"bom-ref"`
			Type string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &bom); err != nil || bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" || len(bom.Components) != len(comps) {
		t.Fatalf("bad CycloneDX: %v %+v", err, bom)
	}
	refs := map[string]bool{}
	for _, c := range bom.Components {
		if refs[c.Ref] || c.Type == "" {
			t.Errorf("duplicate or untyped component %q", c.Ref)
		}
		refs[c.Ref] = true
	}
}

func TestSBOMDropsCredentialsInModuleSources(t *testing.T) {
	src := "git::https://oauth2:" + "glpat-AbCdEf123456" + "@gitlab.example.com/infra/net.git?ref=v1.2.0"
	if got := stripURLUser(src); got != "git::https://gitlab.example.com/infra/net.git?ref=v1.2.0" {
		t.Fatalf("got %q", got)
	}
}
