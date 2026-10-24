# expect: TG-AZ-NSG-001, TG-AZ-ST-001
resource "azurerm_network_security_rule" "rdp" {
  name                   = "rdp"
  direction              = "Inbound"
  access                 = "Allow"
  protocol               = "Tcp"
  source_address_prefix  = "*"
  destination_port_range = "3389"
}
resource "azurerm_storage_account" "s" {
  name                            = "acme"
  min_tls_version                 = "TLS1_0"
  allow_nested_items_to_be_public = true
}
