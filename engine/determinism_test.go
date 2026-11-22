package engine

import (
	"slices"
	"testing"
)

// Map iteration is random in Go; the same input must still name the same variable
// and give the same graph on every run.
func TestViaAndGraphAreDeterministic(t *testing.T) {
	r := &Resource{Via: map[string]string{"rotation.0.b": "var.b", "rotation.0.a": "var.a", "rotation.0.c": "var.c"}}
	for i := 0; i < 50; i++ {
		if got := r.via("rotation"); got != "var.a" {
			t.Fatalf("via = %q, want var.a (the first key in sorted order)", got)
		}
	}
	src := `
resource "aws_iam_role" "r" { name = "r" }
data "aws_iam_policy_document" "d" { statement { actions = ["s3:GetObject"] } }
resource "aws_iam_role_policy" "p" {
  role   = aws_iam_role.r.id
  policy = data.aws_iam_policy_document.d.json
}
resource "aws_iam_role_policy" "q" {
  role   = aws_iam_role.r.id
  policy = data.aws_iam_policy_document.d.json
}
`
	first := Scan(Input{Files: map[string]string{"main.tf": src}}).Graph.Edges
	if !slices.IsSortedFunc(first, func(a, b Edge) int {
		if a.Source != b.Source {
			if a.Source < b.Source {
				return -1
			}
			return 1
		}
		if a.Target < b.Target {
			return -1
		}
		if a.Target > b.Target {
			return 1
		}
		return 0
	}) {
		t.Fatalf("edges not sorted: %v", first)
	}
	for i := 0; i < 20; i++ {
		if got := Scan(Input{Files: map[string]string{"main.tf": src}}).Graph.Edges; !slices.Equal(got, first) {
			t.Fatalf("run %d: edges %v, want %v", i, got, first)
		}
	}
}
