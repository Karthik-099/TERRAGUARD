# path: examples/data-sources/hpe_morpheus_cluster/example-name.tf
# forbid: TG-VAL-003, TG-TF-008, TG-VAL-010, TG-STATE-003
# A provider documentation snippet: it assumes var.cluster_name exists and
# shows a lookup without using it.
data "hpe_morpheus_cluster" "example" {
  name = var.cluster_name
}
