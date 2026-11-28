package engine

import (
	"sort"
	"strings"
)

// The hpegl to HPE migration report. Everything in it is from two guides of
// terraform-provider-hpe v2.3.0: docs/guides/hpegl_to_hpe_migration.md
// (type tables, import IDs, provider block mapping) and
// docs/guides/tfmigrator_migration.md (commands), plus
// docs/guides/tfmigrator_troubleshooting.md for the instance note.

// MigrationItem is one hpegl resource or data source and what replaces it.
type MigrationItem struct {
	Address     string   `json:"address"`
	Mode        string   `json:"mode"` // managed or data
	Type        string   `json:"type"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Replacement string   `json:"replacement,omitempty"` // empty: none in the guide
	Notes       []string `json:"notes,omitempty"`
}

// MigrationMapping is one hpegl provider setting and where it goes in the hpe provider.
type MigrationMapping struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// MigrationProvider is one hpegl provider block and the hpe block that replaces it.
type MigrationProvider struct {
	File    string             `json:"file"`
	Line    int                `json:"line"`
	Mode    string             `json:"mode,omitempty"` // glcs, glp or direct; empty without a vmaas block
	Mapping []MigrationMapping `json:"mapping,omitempty"`
	Notes   []string           `json:"notes,omitempty"`
}

// MigrationReport lists what moving from HPE/hpegl to HPE/hpe involves.
type MigrationReport struct {
	Items         []MigrationItem     `json:"items"`
	Replaceable   int                 `json:"replaceable"`
	NoReplacement int                 `json:"no_replacement"`
	Providers     []MigrationProvider `json:"providers"`
	Notes         []string            `json:"notes"`
	Commands      []string            `json:"commands"`
	Guides        []string            `json:"guides"`
}

// hpeImportIDs: "Composite Import IDs" table of hpegl_to_hpe_migration.md.
var hpeImportIDs = map[string]string{
	"hpegl_vmaas_router_bgp_neighbor":          "{router_id}.{id}",
	"hpegl_vmaas_router_nat_rule":              "{router_id}.{id}",
	"hpegl_vmaas_router_route":                 "{router_id}.{id}",
	"hpegl_vmaas_router_firewall_rule_group":   "{router_id}.{id}",
	"hpegl_vmaas_dhcp_server":                  "{network_server_id}.{id}",
	"hpegl_vmaas_load_balancer_monitor":        "{lb_id}.{id}",
	"hpegl_vmaas_load_balancer_virtual_server": "{lb_id}.{id}",
	"hpegl_vmaas_load_balancer_pool":           "{lb_id}/{id}",
	"hpegl_vmaas_load_balancer_profile":        "{lb_id}/{id}",
}

// hpeMigrationCommands: the full pipeline of tfmigrator_migration.md ("Required
// Inputs", "Full Pipeline (migrate)" and "Next steps after migrate"), verbatim.
var hpeMigrationCommands = []string{
	"terraform show -json > state.json",
	"tfmigrator migrate --state state.json --working-dir . --var-file terraform.tfvars --original .",
	"cd migrated/final",
	"terraform init",
	"terraform fmt",
	"terraform validate",
	"terraform plan",
	"terraform apply --refresh-only",
	"terraform apply",
}

// hpeProviderMappings: "Provider Block Transformation" of hpegl_to_hpe_migration.md.
var hpeProviderMappings = map[string][]MigrationMapping{
	"glcs": {
		{"iam_service_url", "morpheus.pce_identity.issuer_url"},
		{"vmaas.location", "morpheus.pce_identity.location"},
		{"vmaas.space_name", "morpheus.pce_identity.space"},
		{"vmaas.broker_url", "morpheus.pce_identity.broker_url"},
		{"(new)", "morpheus.pce_identity.client_id = var.hpe_pce_client_id"},
		{"(new)", "morpheus.pce_identity.client_secret = var.hpe_pce_client_secret"},
	},
	"glp": {
		{"iam_service_url", "morpheus.pce_disconnected_identity.token_issuer_url"},
		{"vmaas.location", "morpheus.pce_disconnected_identity.location"},
		{"vmaas.space_name", "morpheus.pce_disconnected_identity.workspace_id"},
		{"vmaas.broker_url", "morpheus.pce_disconnected_identity.broker_url"},
		{"(new)", "morpheus.pce_disconnected_identity.client_id = var.hpe_pce_client_id"},
		{"(new)", "morpheus.pce_disconnected_identity.client_secret = var.hpe_pce_client_secret"},
	},
	"direct": {
		{"vmaas.morpheus_url", "morpheus.url"},
		{"vmaas.morpheus_token", "morpheus.access_token"},
	},
}

// HPEMigration reports every hpegl_* resource and data source in files, its
// hpe_* replacement, the provider block change and the tfmigrator commands.
func HPEMigration(files map[string]string) *MigrationReport {
	m := Parse(files)
	rep := &MigrationReport{Items: []MigrationItem{}, Providers: []MigrationProvider{}, Commands: hpeMigrationCommands,
		Guides: []string{"docs/guides/hpegl_to_hpe_migration.md", "docs/guides/tfmigrator_migration.md", "docs/guides/tfmigrator_troubleshooting.md"},
		Notes: []string{
			"Prerequisites: Terraform >= 1.5.0 (import blocks) and the HPE provider >= 2.0.0: required_providers { hpe = { source = \"HPE/hpe\", version = \">= 2.0.0\" } }.",
			"Every hpegl VMaaS resource has a different schema in the HPE provider; tfmigrator generates each new resource from state with an import block. After the import, terraform plan must show no changes.",
			"tfmigrator migrate-providers writes the hpe provider block, credential variable blocks and credentials.auto.tfvars.",
			"Environment: iam_version falls back to HPEGL_IAM_VERSION (default glcs) and decides the generated block. The HPE provider docs document no environment variables for the morpheus block.",
		}}
	for _, r := range m.Resources {
		if r.Format != "" || r.FromPlan || !strings.HasPrefix(r.Type, "hpegl_") {
			continue
		}
		mode := "managed"
		if r.Mode == "data" {
			mode = "data"
		}
		it := MigrationItem{Address: r.Address, Mode: mode, Type: r.Type, File: r.File, Line: r.Line, Replacement: hpeMigration[mode][r.Type]}
		switch {
		case r.Type == "hpegl_vmaas_morpheus_details" && mode == "data":
			it.Notes = []string{"Removed: no HPE equivalent; the provider block transformation (migrate-providers) replaces it."}
		case it.Replacement == "":
			it.Notes = []string{"No replacement in HPE's hpegl to HPE guide, which covers hpegl VMaaS types only."}
		case mode == "data":
			it.Notes = []string{"Change the data source type (tfmigrator migrate-datasources)."}
		default:
			it.Notes = []string{"Schema differs: generated from state with an import block."}
			if id := hpeImportIDs[r.Type]; id != "" {
				it.Notes = append(it.Notes, "Import ID: "+id+".")
			}
			if r.Type == "hpegl_vmaas_instance" {
				it.Notes = append(it.Notes, `config_vmware.nested_virtualization must be "on" or "off" (HPE provider 2.0.0 or later).`)
			}
		}
		if it.Replacement == "" {
			rep.NoReplacement++
		} else {
			rep.Replaceable++
		}
		rep.Items = append(rep.Items, it)
	}
	sort.SliceStable(rep.Items, func(i, j int) bool {
		a, b := rep.Items[i], rep.Items[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	for _, b := range m.Blocks {
		if b.Kind != "provider" || len(b.Labels) != 1 || b.Labels[0] != "hpegl" {
			continue
		}
		p := MigrationProvider{File: b.File, Line: b.Line}
		iam, _ := get(b.Attrs, "iam_version").(string)
		switch {
		case get(b.Attrs, "vmaas") == nil:
			p.Notes = []string{"No vmaas block: the guide's provider transformation covers VMaaS only."}
		case get(b.Attrs, "vmaas.morpheus_url") != nil:
			p.Mode = "direct"
			p.Notes = []string{"Direct connection to Morpheus: no pce_identity block."}
		case iam == "glp":
			p.Mode = "glp"
			p.Notes = []string{"GreenLake IAM, disconnected (iam_version = \"glp\")."}
		default:
			p.Mode = "glcs"
			p.Notes = []string{"GreenLake IAM, connected (iam_version = \"glcs\", the default)."}
			if iam != "glcs" {
				p.Notes = append(p.Notes, "iam_version is not set in the code: HPEGL_IAM_VERSION decides; glp gives morpheus.pce_disconnected_identity instead.")
			}
		}
		p.Mapping = hpeProviderMappings[p.Mode]
		rep.Providers = append(rep.Providers, p)
	}
	sort.SliceStable(rep.Providers, func(i, j int) bool {
		if rep.Providers[i].File != rep.Providers[j].File {
			return rep.Providers[i].File < rep.Providers[j].File
		}
		return rep.Providers[i].Line < rep.Providers[j].Line
	})
	return rep
}
