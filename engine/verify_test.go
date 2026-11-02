package engine

import (
	"strings"
	"testing"
)

func TestVerifyRejectsDeletingResources(t *testing.T) {
	before := Scan(Input{Files: map[string]string{"main.tf": `resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"
}
resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
}`}})
	// "Fixing" by deleting the public bucket removes its findings but loses data.
	deleted := Scan(Input{Files: map[string]string{"main.tf": `resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
}`}})
	if ok, why := Verify(before, deleted); ok || !strings.Contains(why, "aws_s3_bucket.data") {
		t.Fatalf("deleting a resource was accepted: %s", why)
	}
	fixed := Scan(Input{Files: map[string]string{"main.tf": `resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "private"
}
resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
}`}})
	if ok, why := Verify(before, fixed); !ok {
		t.Fatalf("a real fix was rejected: %s", why)
	}
}
