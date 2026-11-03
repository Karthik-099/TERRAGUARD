package engine

import (
	"reflect"
	"testing"
)

func TestBuildInventory(t *testing.T) {
	files := map[string]string{"main.tf": `
resource "aws_s3_bucket" "logs" {}
resource "aws_s3_bucket" "new" {}
resource "aws_instance" "web" { count = 2 }
data "aws_caller_identity" "me" {}
`}
	raw := `{"version":4,"resources":[
 {"mode":"managed","type":"aws_s3_bucket","name":"logs","instances":[{}]},
 {"mode":"managed","type":"aws_instance","name":"web","instances":[{"index_key":0},{"index_key":1}]},
 {"mode":"managed","type":"aws_iam_role","name":"old","instances":[{}]},
 {"module":"module.vpc","mode":"managed","type":"aws_vpc","name":"this","instances":[{}]},
 {"mode":"data","type":"aws_caller_identity","name":"me","instances":[{}]}]}`
	show := `{"values":{"root_module":{"resources":[
 {"address":"aws_s3_bucket.logs","mode":"managed","type":"aws_s3_bucket"},
 {"address":"aws_instance.web[0]","mode":"managed","type":"aws_instance"},
 {"address":"aws_instance.web[1]","mode":"managed","type":"aws_instance"},
 {"address":"aws_iam_role.old","mode":"managed","type":"aws_iam_role"}],
 "child_modules":[{"resources":[{"address":"module.vpc.aws_vpc.this","mode":"managed","type":"aws_vpc"}]}]}}}`
	for name, state := range map[string]string{"tfstate": raw, "show": show} {
		inv, err := BuildInventory(files, state)
		if err != nil {
			t.Fatal(name, err)
		}
		if inv.InCode != 3 || inv.InState != 5 || inv.Matched != 2 || inv.ModuleState != 1 || inv.StateByType["aws_instance"] != 2 {
			t.Errorf("%s: counts %+v", name, inv)
		}
		if !reflect.DeepEqual(inv.NotApplied, []string{"aws_s3_bucket.new"}) || !reflect.DeepEqual(inv.NotInCode, []string{"aws_iam_role.old"}) {
			t.Errorf("%s: lists %v %v", name, inv.NotApplied, inv.NotInCode)
		}
	}
	if _, err := BuildInventory(files, `{"x":1}`); err == nil {
		t.Error("want an error for a document that is not state")
	}
}
