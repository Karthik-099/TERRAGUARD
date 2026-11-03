package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// Inventory compares the managed resources a root module declares with the
// ones its state records. Resources inside child modules are counted, not
// matched, because code addresses here carry no module path.
type Inventory struct {
	InCode       int            `json:"in_code"`
	InState      int            `json:"in_state"`
	Matched      int            `json:"matched"`
	NotApplied   []string       `json:"not_applied,omitempty"`   // in code, not in state
	NotInCode    []string       `json:"not_in_code,omitempty"`   // in state, not in code: apply would destroy them
	ModuleState  int            `json:"module_state,omitempty"`  // state instances inside child modules
	StateByType  map[string]int `json:"state_by_type,omitempty"` // instances per type, all modules
	StateVersion int            `json:"state_version,omitempty"`
}

var instanceKey = regexp.MustCompile(`\[[^\]]*\]$`)

// BuildInventory reads state as a raw terraform.tfstate (version 4) or the
// output of `terraform show -json`, and compares it with the root module code.
func BuildInventory(files map[string]string, state string) (*Inventory, error) {
	var raw struct {
		Version   int `json:"version"`
		Resources []struct {
			Module    string `json:"module"`
			Mode      string `json:"mode"`
			Type      string `json:"type"`
			Name      string `json:"name"`
			Instances []any  `json:"instances"`
		} `json:"resources"`
		Values *struct {
			RootModule showModule `json:"root_module"`
		} `json:"values"`
	}
	if err := json.Unmarshal([]byte(state), &raw); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	inv := &Inventory{StateByType: map[string]int{}, StateVersion: raw.Version}
	root := map[string]bool{}
	switch {
	case raw.Values != nil:
		var walk func(m showModule, top bool)
		walk = func(m showModule, top bool) {
			for _, r := range m.Resources {
				if r.Mode != "managed" {
					continue
				}
				inv.InState++
				inv.StateByType[r.Type]++
				if top {
					root[instanceKey.ReplaceAllString(r.Address, "")] = true
				} else {
					inv.ModuleState++
				}
			}
			for _, c := range m.ChildModules {
				walk(c, false)
			}
		}
		walk(raw.Values.RootModule, true)
	case raw.Version >= 3:
		for _, r := range raw.Resources {
			if r.Mode != "managed" {
				continue
			}
			n := max(len(r.Instances), 1)
			inv.InState += n
			inv.StateByType[r.Type] += n
			if r.Module == "" {
				root[r.Type+"."+r.Name] = true
			} else {
				inv.ModuleState += n
			}
		}
	default:
		return nil, fmt.Errorf("state: not a terraform.tfstate or `terraform show -json` document")
	}
	code := map[string]bool{}
	for _, r := range Parse(files).Resources {
		if r.Mode == "managed" && r.Format == "" {
			code[r.Address] = true
		}
	}
	inv.InCode = len(code)
	for a := range code {
		if root[a] {
			inv.Matched++
		} else {
			inv.NotApplied = append(inv.NotApplied, a)
		}
	}
	for a := range root {
		if !code[a] {
			inv.NotInCode = append(inv.NotInCode, a)
		}
	}
	sort.Strings(inv.NotApplied)
	sort.Strings(inv.NotInCode)
	return inv, nil
}

type showModule struct {
	Resources []struct {
		Address string `json:"address"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
	} `json:"resources"`
	ChildModules []showModule `json:"child_modules"`
}
