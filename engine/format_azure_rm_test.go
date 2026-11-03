package engine

import (
	"strings"
	"testing"
)

const armTemplate = `{
  // comments are allowed in ARM templates
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "parameters": {
    "acct": {"type": "string", "defaultValue": "mystore01"},
    "pw": {"type": "secureString", "defaultValue": "hunter2hunter2"},
    "open": {"type": "string"}
  },
  "variables": {"tls": "TLS1_0", "name2": "[concat(parameters('acct'), 'b')]"},
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2018-02-01",
      "name": "[parameters('acct')]",
      "properties": {
        "minimumTlsVersion": "[variables('tls')]",
        "networkAcls": {"defaultAction": "[parameters('open')]"}
      },
      "resources": [
        {"type": "blobServices/containers", "apiVersion": "2022-09-01", "name": "default/public", "properties": {"publicAccess": "Container"}}
      ]
    },
    {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01", "name": "[variables('name2')]", "copy": {"name": "loop", "count": 3},
     "properties": {"supportsHttpsTrafficOnly": true}},
    {"type": "Microsoft.Sql/servers", "apiVersion": "2022-05-01-preview", "name": "sql1", "properties": {}},
    {"type": "Microsoft.Sql/servers/firewallRules", "apiVersion": "2022-05-01-preview", "name": "sql1/all",
     "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}},
    {"type": "microsoft.network/networksecuritygroups", "apiVersion": "2023-04-01", "name": "nsg",
     "properties": {"securityRules": [{"name": "ssh", "properties": {"access": "Allow", "direction": "Inbound", "protocol": "Tcp",
       "destinationPortRange": "20-25", "sourceAddressPrefix": "Internet"}}]}}
  ]
}`

func TestParseARM(t *testing.T) {
	rs, syntax := parseARM("main.json", armTemplate)
	if len(syntax) > 0 {
		t.Fatal(syntax)
	}
	by := map[string]*Resource{}
	for _, r := range rs {
		by[r.Address] = r
	}
	st := by["Microsoft.Storage/storageAccounts.mystore01"]
	if st == nil {
		t.Fatalf("parameter default not used for the name: %v", by)
	}
	if v := st.get("properties.minimumTlsVersion"); v != "TLS1_0" {
		t.Errorf("variable not resolved: %v", v)
	}
	if !isUnknown(st.get("properties.networkAcls.defaultAction")) {
		t.Error("a parameter without a default must be Unknown")
	}
	if st.Line != 11 || st.line("properties.minimumTlsVersion") != 16 {
		t.Errorf("lines: %d %d", st.Line, st.line("properties.minimumTlsVersion"))
	}
	if by["Microsoft.Storage/storageAccounts/blobServices/containers.mystore01/default/public"] == nil {
		t.Errorf("nested child missing: %v", by)
	}
	if by["Microsoft.Storage/storageAccounts.mystore01b"] == nil {
		t.Error("concat of a variable not resolved")
	}
	if nsg := by["Microsoft.Network/networkSecurityGroups.nsg"]; nsg == nil {
		t.Error("type not matched case-insensitively")
	}
	if by["parameter.pw"] == nil || by["parameter.acct"] != nil {
		t.Error("only secure parameters become resources")
	}
	if kids := armChildren(by["Microsoft.Sql/servers.sql1"], "firewallRules"); len(kids) != 1 {
		t.Error("top-level child not linked to its parent")
	}
	if _, syntax := parseARM("bad.json", `{"$schema": "deploymentTemplate.json#", "resources": [`); len(syntax) != 1 {
		t.Error("broken JSON must give a syntax finding")
	}
}

func TestARMSymbolicResources(t *testing.T) {
	src := `{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", "languageVersion": "2.0",
  "resources": {"kv": {"type": "Microsoft.KeyVault/vaults", "apiVersion": "2023-07-01", "name": "vault1", "properties": {"publicNetworkAccess": "Enabled"}}}}`
	rs, _ := parseARM("main.json", src)
	if len(rs) != 1 || rs[0].Address != "Microsoft.KeyVault/vaults.vault1" {
		t.Fatalf("got %v", rs)
	}
}

func TestARMRules(t *testing.T) {
	got := map[string]bool{}
	for _, f := range Scan(Input{Files: map[string]string{"main.json": armTemplate}}).Findings {
		got[f.RuleID+" "+f.Resource] = true
	}
	for _, want := range []string{
		"TG-ARM-ST-206 Microsoft.Storage/storageAccounts.mystore01",
		"TG-ARM-ST-201 Microsoft.Storage/storageAccounts.mystore01",
		"TG-ARM-ST-202 Microsoft.Storage/storageAccounts/blobServices/containers.mystore01/default/public",
		"TG-ARM-SQL-201 Microsoft.Sql/servers.sql1",
		"TG-ARM-SQL-202 Microsoft.Sql/servers.sql1",
		"TG-ARM-NSG-202 Microsoft.Network/networkSecurityGroups.nsg",
		"TG-ARM-PARAM-201 parameter.pw",
	} {
		if !got[want] {
			t.Errorf("missing %s", want)
		}
	}
	for _, not := range []string{
		"TG-ARM-ST-203 Microsoft.Storage/storageAccounts.mystore01", // Unknown default action
		"TG-ARM-ST-201 Microsoft.Storage/storageAccounts.mystore01b",
		"TG-ARM-NSG-201 Microsoft.Network/networkSecurityGroups.nsg",
	} {
		if got[not] {
			t.Errorf("unexpected %s", not)
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "TG-VAL-001") {
			t.Errorf("syntax finding: %s", k)
		}
	}
}
