package engine

import "testing"

// Fuzz targets: any input must produce a report, never a panic. CI runs each
// briefly; run longer locally with go test ./engine -fuzz FuzzScan -fuzztime 5m.

func FuzzScan(f *testing.F) {
	f.Add(`resource "aws_s3_bucket" "b" { acl = "public-read" }`, "")
	f.Add(`module "m" { source = "./x" }`, `{"resource_changes":[]}`)
	f.Add(`variable "v" { default = "${foo}" }`, "{")
	f.Fuzz(func(t *testing.T, src, plan string) {
		r := Scan(Input{Files: map[string]string{"main.tf": src, "x/main.tf": src}, Plan: plan})
		if r == nil {
			t.Fatal("nil report")
		}
		_ = Markdown(r)
		_, _ = SARIF(r)
	})
}

func FuzzConfig(f *testing.F) {
	f.Add("fail_on: HIGH\ncustom_rules:\n  - id: X\n    attribute: tags.owner\n    exists: true\n")
	f.Add("waivers:\n  - rule: TG-*\n    expires: 2020-01-01\n")
	f.Fuzz(func(t *testing.T, cfg string) {
		Scan(Input{Files: map[string]string{"main.tf": `resource "aws_s3_bucket" "b" {}`}, Config: cfg})
	})
}

// Every format parser must survive arbitrary input: no panic, no hang.
func FuzzFormats(f *testing.F) {
	f.Add("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {containers: [{name: c, image: x}]}\n")
	f.Add("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B: {Type: AWS::S3::Bucket, Properties: {BucketName: !Ref X}}\n")
	f.Add(`{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","resources":[{"type":"Microsoft.Storage/storageAccounts","name":"[parameters('n')]"}]}`)
	f.Add("FROM alpine\nRUN echo \\\n  hi\nUSER 1000\n")
	f.Add("on: push\njobs: {a: {runs-on: x, steps: [{run: echo}]}}\n")
	f.Add("- hosts: all\n  tasks: [{name: t, shell: ls}]\n")
	f.Add("openapi: 3.0.0\npaths: {/a: {get: {}}}\n")
	names := []string{"k.yaml", "template.yaml", "azuredeploy.json", "Dockerfile", ".github/workflows/ci.yml", "site.yml", "api.yaml",
		"docker-compose.yml", ".gitlab-ci.yml", "serverless.yml", "x.tf.json"}
	f.Fuzz(func(t *testing.T, src string) {
		for _, n := range names {
			Scan(Input{Files: map[string]string{n: src}})
		}
	})
}
