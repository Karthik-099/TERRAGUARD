//go:build js && wasm

// Command wasm exposes the engine to the browser as globalThis.terraguard, so
// the GitHub Pages site analyzes Terraform locally with no backend.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// jsonFn wraps f as a JS function taking and returning JSON strings.
func jsonFn(f func(in engine.Input) any) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		var in engine.Input
		if len(args) > 0 {
			if err := json.Unmarshal([]byte(args[0].String()), &in); err != nil {
				return `{"error":"invalid input JSON"}`
			}
		}
		b, _ := json.Marshal(f(in))
		return string(b)
	})
}

func main() {
	js.Global().Set("terraguard", js.ValueOf(map[string]any{
		"version": engine.Version,
		"scan":    jsonFn(func(in engine.Input) any { return engine.Scan(in) }),
		"fixAll": jsonFn(func(in engine.Input) any {
			changed, errs := engine.FixAll(in)
			msgs := []string{}
			for _, e := range errs {
				msgs = append(msgs, e.Error())
			}
			return map[string]any{"files": changed, "errors": msgs}
		}),
		"applyFixes": js.FuncOf(func(_ js.Value, args []js.Value) any {
			var in struct {
				Files map[string]string `json:"files"`
				Fixes []*engine.Fix     `json:"fixes"`
			}
			if len(args) == 0 || json.Unmarshal([]byte(args[0].String()), &in) != nil {
				return `{"error":"invalid input JSON"}`
			}
			changed, errs := engine.ApplyFixes(in.Files, in.Fixes)
			msgs := []string{}
			for _, e := range errs {
				msgs = append(msgs, e.Error())
			}
			b, _ := json.Marshal(map[string]any{"files": changed, "errors": msgs})
			return string(b)
		}),
		// render(inputJSON, "markdown"|"sarif"|"json") -> report text
		"render": js.FuncOf(func(_ js.Value, args []js.Value) any {
			var in engine.Input
			if len(args) < 2 || json.Unmarshal([]byte(args[0].String()), &in) != nil {
				return ""
			}
			rep := engine.Scan(in)
			switch args[1].String() {
			case "markdown":
				return engine.Markdown(rep)
			case "sarif":
				b, _ := engine.SARIF(rep)
				return string(b)
			case "junit":
				b, _ := engine.JUnit(rep)
				return string(b)
			case "codequality":
				b, _ := engine.CodeQuality(rep)
				return string(b)
			}
			b, _ := json.MarshalIndent(rep, "", "  ")
			return string(b)
		}),
		// fmt(src) -> terraform fmt output
		"fmt": js.FuncOf(func(_ js.Value, args []js.Value) any {
			return string(hclwrite.Format([]byte(args[0].String())))
		}),
		"docs": js.FuncOf(func(_ js.Value, args []js.Value) any {
			var in engine.Input
			if len(args) == 0 || json.Unmarshal([]byte(args[0].String()), &in) != nil {
				return ""
			}
			return engine.Docs(in.Files)
		}),
		// verifyChange({files, plan, config, changed}) scans before and after a
		// proposed edit and returns the engine's accept/reject decision.
		"verifyChange": js.FuncOf(func(_ js.Value, args []js.Value) any {
			var in struct {
				engine.Input
				Changed map[string]string `json:"changed"`
			}
			if len(args) == 0 || json.Unmarshal([]byte(args[0].String()), &in) != nil {
				return `{"error":"invalid input JSON"}`
			}
			before := engine.Scan(in.Input)
			after := in.Input
			after.Files = map[string]string{}
			for k, v := range in.Files {
				after.Files[k] = v
			}
			for k, v := range in.Changed {
				after.Files[k] = v
			}
			rep := engine.Scan(after)
			ok, reason := engine.Verify(before, rep)
			b, _ := json.Marshal(map[string]any{"ok": ok, "reason": reason, "before": engine.RiskWeight(before), "after": engine.RiskWeight(rep)})
			return string(b)
		}),
		"agentsMD": js.FuncOf(func(_ js.Value, args []js.Value) any {
			var in engine.Input
			if len(args) == 0 || json.Unmarshal([]byte(args[0].String()), &in) != nil {
				return ""
			}
			return engine.AgentsMD(in.Files, in.Config)
		}),
		"rules": jsonFn(func(engine.Input) any { return engine.Catalog() }),
	}))
	select {}
}
