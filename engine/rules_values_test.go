package engine

import (
	"strings"
	"testing"
)

func valueHits(t *testing.T, src string) []string {
	t.Helper()
	var out []string
	for _, r := range Parse(map[string]string{"main.tf": src}).Resources {
		for _, h := range checkAWSValues(r) {
			out = append(out, h.Msg)
		}
	}
	return out
}

func TestAWSValues(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"bad instance type", `resource "aws_instance" "a" { instance_type = "t3.micr" }`, `did you mean "t3.micro"`},
		{"bad rds engine", `resource "aws_db_instance" "a" { engine = "postgresql" }`, `did you mean "postgres"`},
		{"name too long", `resource "aws_iam_role" "a" { name = "` + strings.Repeat("r", 65) + `" }`, "longer than the maximum of 64"},
		{"pattern", `resource "aws_iam_role" "a" { name = "has space" }`, "does not match the pattern"},
		{"valid", `resource "aws_instance" "a" { instance_type = "t3.micro" }` + "\n" + `resource "aws_lb_target_group" "b" { protocol = "https" }`, ""},
		{"unknown", `variable "t" {}` + "\n" + `resource "aws_instance" "a" { instance_type = var.t }`, ""},
		{"via variable skips length", `variable "p" { default = "" }` + "\n" + `resource "aws_iam_role" "a" { name = "${var.p}-x y" }`, ""},
	}
	for _, c := range cases {
		got := valueHits(t, c.src)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected %v", c.name, got)
			}
			continue
		}
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("%s: got %v, want one hit containing %q", c.name, got, c.want)
		}
	}
	if !valueRules[0].Blocking || !valueRules[0].applies("aws_instance") {
		t.Error("TG-VAL-020 must be blocking and cover aws_instance")
	}
}
