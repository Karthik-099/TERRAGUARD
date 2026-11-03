package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// runDrift is the opt-in inventory and drift check. With --state it only reads
// a file. With --live it runs `terraform plan -refresh-only` (no lock, no
// writes) and `terraform show -json`, using whatever credentials terraform
// already has; nothing is changed in the cloud or in state.
func runDrift(args []string) (int, error) {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	statePath := fs.String("state", "", "terraform.tfstate or `terraform show -json` output to compare with the code")
	live := fs.Bool("live", false, "refresh-only plan with terraform (read-only) to find changes made outside Terraform")
	format := fs.String("format", "text", "text or json")
	failOnDrift := fs.Bool("fail", false, "exit 1 when anything drifted or is out of step")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return 2, err
	}
	dir := "."
	if len(paths) > 0 {
		dir = paths[0]
	}
	if *statePath == "" && !*live {
		return 2, errors.New("usage: terraguard drift [dir] --state terraform.tfstate | --live")
	}
	in, err := buildInput([]string{dir}, "", "", "")
	if err != nil {
		return 2, err
	}
	root := map[string]string{} // the root module only: inventory addresses have no module path
	for name, src := range in.Files {
		if filepath.Dir(filepath.FromSlash(name)) == filepath.Clean(dir) {
			root[name] = src
		}
	}
	var state []byte
	var drift []engine.PlanChange
	if *live {
		tmp, err := os.MkdirTemp("", "terraguard-drift")
		if err != nil {
			return 2, err
		}
		defer os.RemoveAll(tmp)
		planFile := filepath.Join(tmp, "refresh.tfplan")
		if out, err := terraform(dir, "plan", "-refresh-only", "-lock=false", "-input=false", "-no-color", "-out="+planFile); err != nil {
			return 2, fmt.Errorf("terraform plan -refresh-only: %v\n%s", err, out)
		}
		plan, err := terraform(dir, "show", "-json", planFile)
		if err != nil {
			return 2, fmt.Errorf("terraform show: %v", err)
		}
		if rep := engine.Scan(engine.Input{Plan: string(plan)}); rep.Plan != nil {
			drift = rep.Plan.Drift
		}
		if state, err = terraform(dir, "show", "-json"); err != nil {
			return 2, fmt.Errorf("terraform show: %v", err)
		}
	} else if state, err = os.ReadFile(*statePath); err != nil {
		return 2, err
	}
	inv, err := engine.BuildInventory(root, string(state))
	if err != nil {
		return 2, err
	}
	if *format == "json" {
		b, _ := json.MarshalIndent(map[string]any{"inventory": inv, "drift": drift}, "", "  ")
		fmt.Println(string(b))
	} else {
		printDrift(inv, drift, *live)
	}
	if *failOnDrift && (len(drift) > 0 || len(inv.NotApplied) > 0 || len(inv.NotInCode) > 0) {
		return 1, nil
	}
	return 0, nil
}

func printDrift(inv *engine.Inventory, drift []engine.PlanChange, live bool) {
	fmt.Printf("Inventory: %d resources in code, %d instances in state (%d in child modules), %d matched\n", inv.InCode, inv.InState, inv.ModuleState, inv.Matched)
	for _, a := range inv.NotApplied {
		fmt.Println("  not applied yet:", a)
	}
	for _, a := range inv.NotInCode {
		fmt.Println("  in state, not in code (apply would destroy it):", a)
	}
	if !live {
		fmt.Println("Drift: not checked (add --live to compare state with the real infrastructure)")
		return
	}
	if len(drift) == 0 {
		fmt.Println("Drift: none, the infrastructure matches state")
	}
	for _, d := range drift {
		fmt.Printf("  drifted: %s %s %v\n", d.Address, d.Action, d.Reasons)
	}
}

func terraform(dir string, args ...string) ([]byte, error) {
	bin := "terraform"
	if _, err := exec.LookPath(bin); err != nil {
		if _, err := exec.LookPath("tofu"); err == nil {
			bin = "tofu"
		}
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.Stderr, err
	}
	return out, err
}
