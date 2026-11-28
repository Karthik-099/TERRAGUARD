package engine

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestHPEMigrationGolden(t *testing.T) {
	src, err := os.ReadFile("testdata/hpe_migrate/main.tf")
	if err != nil {
		t.Fatal(err)
	}
	rep := HPEMigration(map[string]string{"main.tf": string(src)})
	if len(rep.Items) != 3 || rep.Replaceable != 2 || rep.NoReplacement != 1 {
		t.Fatalf("want 3 items, 2 with a replacement: %+v", rep)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	enc.Encode(rep)
	got := strings.TrimSpace(buf.String())
	const golden = "testdata/hpe_migrate/report.golden.json"
	if *updateGolden {
		os.WriteFile(golden, []byte(got+"\n"), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != got {
		t.Fatalf("migration JSON changed (go test ./engine -run HPEMigrationGolden -update):\n%s", got)
	}
}

func TestHPEMigrationProviderModes(t *testing.T) {
	for src, want := range map[string]string{
		"vmaas {\n morpheus_url = \"https://m\"\n}":            "direct",
		"iam_version = \"glp\"\nvmaas {\n location = \"x\"\n}": "glp",
		"vmaas {\n location = \"x\"\n}":                        "glcs",
		"metal {\n project_id = \"x\"\n}":                      "",
	} {
		rep := HPEMigration(map[string]string{"main.tf": "provider \"hpegl\" {\n" + src + "\n}\n"})
		if len(rep.Providers) != 1 || rep.Providers[0].Mode != want {
			t.Errorf("%s: want mode %q, got %+v", src, want, rep.Providers)
		}
	}
}
