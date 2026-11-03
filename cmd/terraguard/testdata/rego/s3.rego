package main

import rego.v1

deny contains msg if {
	some name
	bucket := input.resource.aws_s3_bucket[name][_]
	not bucket.tags.owner
	msg := sprintf("bucket %s has no owner tag", [name])
}

warn contains msg if {
	some rc in input.resource_changes
	rc.change.actions[_] == "delete"
	msg := sprintf("%s will be deleted", [rc.address])
}
