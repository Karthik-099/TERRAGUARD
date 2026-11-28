# path: modules/cluster/example-name.tf
# expect: TG-VAL-003, TG-TF-008
# The same file in a normal module keeps every check.
data "hpe_morpheus_cluster" "example" {
  name = var.cluster_name
}
