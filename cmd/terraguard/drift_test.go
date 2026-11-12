package main

import (
	"os"
	"testing"
)

// An absolute folder must match the same resources as ".".
func TestDriftAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	os.WriteFile("main.tf", []byte(`resource "aws_s3_bucket" "b" { bucket = "my-bucket-123" }`+"\n"), 0o600)
	os.WriteFile("s.json", []byte(`{"version":4,"resources":[{"mode":"managed","type":"aws_s3_bucket","name":"b","instances":[{}]}]}`), 0o600)
	for _, d := range []string{".", dir} {
		if code, err := runDrift([]string{d, "--state", "s.json", "--fail"}); code != 0 || err != nil {
			t.Errorf("drift %s: code %d, err %v; want everything matched", d, code, err)
		}
	}
}
