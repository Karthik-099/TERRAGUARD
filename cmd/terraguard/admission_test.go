package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdmissionWebhook(t *testing.T) {
	h := admissionHandler("")
	review := func(pod string) map[string]any {
		body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u-1","object":` + pod + `}}`
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/api/k8s/validate", strings.NewReader(body)))
		var out struct {
			Response map[string]any `json:"response"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Response["uid"] != "u-1" {
			t.Fatalf("uid not echoed: %s", rec.Body.String())
		}
		return out.Response
	}
	bad := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"spec":{"hostNetwork":true,"containers":[{"name":"c","image":"nginx","securityContext":{"privileged":true}}]}}`
	if r := review(bad); r["allowed"] != false {
		t.Errorf("a privileged pod on the host network must be denied: %v", r)
	}
	good := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}}`
	if r := review(good); r["allowed"] != true {
		t.Errorf("a plain pod is allowed (warnings at most): %v", r)
	}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/k8s/validate", strings.NewReader("{")))
	if rec.Code != 400 {
		t.Errorf("garbage must be rejected, got %d", rec.Code)
	}
}
