package main

import (
	"strings"
	"testing"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

func TestWriteMigration(t *testing.T) {
	rep := engine.HPEMigration(map[string]string{"main.tf": "data \"hpegl_vmaas_morpheus_details\" \"m\" {}\nresource \"hpegl_vmaas_network\" \"n\" {\n  name = \"n\"\n}\n"})
	for format, want := range map[string]string{
		"text":     ":1 data.hpegl_vmaas_morpheus_details.m -> NO REPLACEMENT",
		"markdown": "`hpegl_vmaas_network.n` -> `hpe_morpheus_network`",
		"json":     `"no_replacement": 1`,
	} {
		var b strings.Builder
		if err := writeMigration(&b, rep, format); err != nil || !strings.Contains(b.String(), want) || !strings.Contains(b.String(), "tfmigrator migrate --state state.json") {
			t.Errorf("%s: %v, missing %q:\n%s", format, err, want, b.String())
		}
	}
	if err := runMigrate([]string{"morpheus"}); err == nil {
		t.Error("only hpegl is supported")
	}
}
