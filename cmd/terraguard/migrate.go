package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// runMigrate prints the hpegl to HPE migration report. It is a report, not a
// gate: it never fails on what it finds.
func runMigrate(args []string) error {
	if len(args) == 0 || args[0] != "hpegl" {
		return errors.New("usage: terraguard migrate hpegl [paths] [--format text|json|markdown]")
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	format := fs.String("format", "text", "text, json or markdown")
	paths, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return err
	}
	if *format != "text" && *format != "json" && *format != "markdown" {
		return fmt.Errorf("--format %q: use text, json or markdown", *format)
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	files, err := loadFiles(paths)
	if err != nil {
		return err
	}
	return writeMigration(os.Stdout, engine.HPEMigration(files), *format)
}

func writeMigration(w io.Writer, rep *engine.MigrationReport, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	md := format == "markdown"
	var b strings.Builder
	head := func(s string) {
		if md {
			fmt.Fprintf(&b, "\n## %s\n\n", s)
		} else {
			fmt.Fprintf(&b, "\n%s\n", s)
		}
	}
	code := func(s string) string {
		if md {
			return "`" + s + "`"
		}
		return s
	}
	if md {
		b.WriteString("# hpegl to HPE migration\n")
	} else {
		b.WriteString("hpegl to HPE migration\n")
	}
	fmt.Fprintf(&b, "%d hpegl resources and data sources: %d with a replacement, %d without.\n", len(rep.Items), rep.Replaceable, rep.NoReplacement)
	if len(rep.Items) > 0 {
		head("Resources")
		for _, it := range rep.Items {
			to := "NO REPLACEMENT"
			if it.Replacement != "" {
				to = code(it.Replacement)
			}
			fmt.Fprintf(&b, "- %s:%d %s -> %s\n", it.File, it.Line, code(it.Address), to)
			for _, n := range it.Notes {
				fmt.Fprintf(&b, "    %s\n", n)
			}
		}
	}
	if len(rep.Providers) > 0 {
		head("Provider block: hpegl -> hpe")
		for _, p := range rep.Providers {
			fmt.Fprintf(&b, "- %s:%d %s\n", p.File, p.Line, strings.Join(p.Notes, " "))
			for _, m := range p.Mapping {
				fmt.Fprintf(&b, "    %s -> %s\n", code(m.From), code(m.To))
			}
		}
	}
	head("Notes")
	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "- %s\n", n)
	}
	head("Commands (HPE tfmigrator guide)")
	if md {
		b.WriteString("```bash\n")
	}
	for _, c := range rep.Commands {
		if md {
			b.WriteString(c + "\n")
		} else {
			b.WriteString("  " + c + "\n")
		}
	}
	if md {
		b.WriteString("```\n")
	}
	fmt.Fprintf(&b, "\nSources, in HPE's terraform-provider-hpe: %s\n", strings.Join(rep.Guides, ", "))
	_, err := io.WriteString(w, b.String())
	return err
}
