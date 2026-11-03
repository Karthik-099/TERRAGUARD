package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// runCost prints an offline monthly cost estimate for a plan and can fail
// when the plan adds more than a budget.
func runCost(args []string) (int, error) {
	fs := flag.NewFlagSet("cost", flag.ContinueOnError)
	plan := fs.String("plan", "", "terraform show -json output; without it the .tf code in the paths is priced")
	usage := fs.String("usage", "", "usage file (YAML) for usage-based charges: requests, storage, data transfer")
	prices := fs.String("prices", "", "price overrides (YAML: price key: USD), e.g. negotiated rates")
	format := fs.String("format", "text", "text, json or markdown")
	failAbove := fs.Float64("fail-above", -1, "exit 1 when the plan adds more than this many USD a month")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	var opts engine.CostOptions
	if opts.Usage, err = readOptional(*usage); err != nil {
		return 2, err
	}
	if opts.Prices, err = readOptional(*prices); err != nil {
		return 2, err
	}
	var est *engine.CostEstimate
	if *plan != "" {
		raw, err := os.ReadFile(*plan)
		if err != nil {
			return 2, err
		}
		est, err = engine.EstimateCostWith(string(raw), opts)
		if err != nil {
			return 2, err
		}
	} else {
		files, err := loadFiles(paths)
		if err != nil {
			return 2, err
		}
		if len(files) == 0 {
			return 2, errors.New("usage: terraguard cost [paths] | --plan plan.json [--usage usage.yml] [--prices prices.yml] [--format text|json|markdown] [--fail-above USD]")
		}
		if est, err = engine.EstimateCostFromCode(files, opts); err != nil {
			return 2, err
		}
	}
	switch *format {
	case "json":
		b, _ := json.MarshalIndent(est, "", "  ")
		fmt.Println(string(b))
	case "markdown":
		fmt.Print(engine.CostMarkdown(est))
	default:
		for _, l := range est.Lines {
			fmt.Printf("%-50s %-40s $%9.2f -> $%9.2f\n", l.Address, l.Detail, l.Before, l.After)
		}
		fmt.Printf("\nMonthly: $%.2f -> $%.2f (%+.2f)\n%s; usage-based charges only from --usage.\n", est.Before, est.After, est.Delta(), est.Basis)
		if len(est.Unpriced) > 0 {
			fmt.Printf("Not priced: %v\n", est.Unpriced)
		}
	}
	if *failAbove >= 0 && est.Delta() > *failAbove {
		fmt.Fprintf(os.Stderr, "cost: the plan adds $%.2f a month, above the $%.2f budget\n", est.Delta(), *failAbove)
		return 1, nil
	}
	return 0, nil
}
