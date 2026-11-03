package engine

import "testing"

// A replace needs both the create and the delete call; a delete needs the delete call.
func TestPermissionNeedsCoverDeletesAndReplaces(t *testing.T) {
	ps := PermissionNeeds(`{"resource_changes":[{"address":"aws_instance.a","mode":"managed","type":"aws_instance","change":{"actions":["delete","create"]}},{"address":"aws_vpc.v","mode":"managed","type":"aws_vpc","change":{"actions":["delete"]}}]}`)
	got := map[string]bool{}
	for _, p := range ps {
		got[p.Action] = true
	}
	for _, w := range []string{"ec2:RunInstances", "ec2:TerminateInstances", "ec2:DeleteVpc"} {
		if !got[w] {
			t.Errorf("missing %s: %v", w, got)
		}
	}
}
