package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"gopkg.in/yaml.v3"
)

// admissionHandler is a Kubernetes validating admission webhook: each object
// the API server sends is checked with the same Kubernetes rules as the
// manifests in a repository. Findings at or above the threshold
// (TERRAGUARD_ADMISSION_FAIL_ON, default HIGH) deny the request; lower ones are
// returned as warnings, which kubectl prints.
func admissionHandler(policy string) http.HandlerFunc {
	failOn := engine.ParseSeverity(os.Getenv("TERRAGUARD_ADMISSION_FAIL_ON"))
	if failOn == "" {
		failOn = engine.High
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var review struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
			Request    *struct {
				UID    string          `json:"uid"`
				Object json.RawMessage `json:"object"`
			} `json:"request"`
		}
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil || review.Request == nil {
			writeJSON(w, 400, map[string]string{"error": "expected an AdmissionReview"})
			return
		}
		resp := map[string]any{"uid": review.Request.UID, "allowed": true}
		var obj any
		if len(review.Request.Object) > 0 && json.Unmarshal(review.Request.Object, &obj) == nil && obj != nil {
			doc, _ := yaml.Marshal(obj)
			rep := engine.Scan(engine.Input{Files: map[string]string{"admission/object.yaml": string(doc)}, Config: policy,
				Frameworks: []string{engine.FormatKubernetes}, FailOn: string(failOn)})
			var deny, warn []string
			for _, f := range rep.Findings {
				if f.Waived {
					continue
				}
				line := fmt.Sprintf("%s %s: %s", f.RuleID, f.Title, f.Message)
				if f.Severity.Rank() >= failOn.Rank() {
					deny = append(deny, line)
				} else if len(warn) < 20 {
					warn = append(warn, line)
				}
			}
			if len(deny) > 0 {
				resp["allowed"] = false
				resp["status"] = map[string]any{"code": 403, "message": "TerraGuard: " + strings.Join(deny, "; ")}
			}
			if len(warn) > 0 {
				resp["warnings"] = warn
			}
		}
		apiVersion := review.APIVersion
		if apiVersion == "" {
			apiVersion = "admission.k8s.io/v1"
		}
		writeJSON(w, 200, map[string]any{"apiVersion": apiVersion, "kind": "AdmissionReview", "response": resp})
	}
}
