# expect: TG-AZ-ARO-001, TG-AZ-ARO-002, TG-AZ-ARO-003, TG-AZ-ARO-004
resource "azurerm_redhat_openshift_cluster" "aro" {
  name                = "aro"
  location            = "eastus"
  resource_group_name = "rg"

  cluster_profile {
    domain  = "aro.example.com"
    version = "4.15.27"
  }
  network_profile {
    pod_cidr     = "10.128.0.0/14"
    service_cidr = "172.30.0.0/16"
  }
  main_profile {
    vm_size   = "Standard_D8s_v3"
    subnet_id = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/main"
  }
  worker_profile {
    vm_size      = "Standard_D4s_v3"
    disk_size_gb = 128
    node_count   = 3
    subnet_id    = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/worker"
  }
  api_server_profile {
    visibility = "Public"
  }
  ingress_profile {
    visibility = "Public"
  }
}
