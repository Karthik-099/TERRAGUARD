// Command schemagen shrinks `terraform providers schema -json` output to what
// TerraGuard's argument checks use (names, required/optional/computed,
// deprecated, block nesting) and writes it gzipped for the engine to embed.
//
//	terraform providers schema -json > schema.json
//	go run ./tools/schemagen -in schema.json -versions aws=6.71.0,azurerm=5.12.0,google=8.9.0
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
)

type attr struct {
	Type       any  `json:"type,omitempty"`
	BlockOK    bool `json:"block_ok,omitempty"`
	Required   bool `json:"required,omitempty"`
	Optional   bool `json:"optional,omitempty"`
	Computed   bool `json:"computed,omitempty"`
	Deprecated bool `json:"deprecated,omitempty"`
}

type block struct {
	Attributes map[string]attr      `json:"attributes,omitempty"`
	BlockTypes map[string]blockType `json:"block_types,omitempty"`
}

type blockType struct {
	Nesting  string `json:"nesting_mode"`
	Block    block  `json:"block"`
	MinItems int    `json:"min_items,omitempty"`
	MaxItems int    `json:"max_items,omitempty"`
}

type entry struct {
	Block block `json:"block"`
}

type provider struct {
	Resources   map[string]entry `json:"resource_schemas,omitempty"`
	DataSources map[string]entry `json:"data_source_schemas,omitempty"`
}

func main() {
	in := flag.String("in", "schema.json", "terraform providers schema -json output")
	out := flag.String("out", "engine/schemas/providers.json.gz", "output file")
	versions := flag.String("versions", "", "provider=version,... of the schemas, for version gating")
	flag.Parse()
	b, err := os.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}
	var s struct {
		Providers map[string]provider `json:"provider_schemas"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		log.Fatal(err)
	}
	vs := map[string]string{}
	for _, kv := range strings.Split(*versions, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vs["registry.terraform.io/hashicorp/"+k] = v
		}
	}
	for _, p := range s.Providers {
		for _, m := range []map[string]entry{p.Resources, p.DataSources} {
			for _, e := range m {
				shrink(&e.Block)
			}
		}
	}
	doc := map[string]any{"provider_schemas": s.Providers, "versions": vs}
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err := json.NewEncoder(zw).Encode(doc); err != nil {
		log.Fatal(err)
	}
	zw.Close()
	f.Close()
	st, _ := os.Stat(*out)
	log.Printf("wrote %s (%d bytes, %d providers)", *out, st.Size(), len(s.Providers))
}

// shrink keeps only whether an attribute is a list of objects, then drops types.
func shrink(b *block) {
	for n, a := range b.Attributes {
		if t, ok := a.Type.([]any); ok && len(t) == 2 && (t[0] == "list" || t[0] == "set") {
			if inner, ok := t[1].([]any); ok && len(inner) > 0 && inner[0] == "object" {
				a.BlockOK = true
			}
		}
		a.Type = nil
		b.Attributes[n] = a
	}
	for n, bt := range b.BlockTypes {
		shrink(&bt.Block)
		b.BlockTypes[n] = bt
	}
}
