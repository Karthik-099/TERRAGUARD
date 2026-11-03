package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUILocalFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "b" {}`), 0o644)
	h := uiHandler(http.NotFoundHandler(), []string{dir}, "tok", "127.0.0.1:9999")
	call := func(method, host, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/local/files", nil)
		req.Host = host
		if token != "" {
			req.Header.Set("X-TerraGuard-Local", token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := call("GET", "127.0.0.1:9999", "tok"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "aws_s3_bucket") {
		t.Fatalf("token holder gets the files: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range []struct{ method, host, token string }{
		{"GET", "127.0.0.1:9999", "wrong"},
		{"GET", "127.0.0.1:9999", ""},
		{"GET", "attacker.example:9999", "tok"}, // DNS rebinding
		{"POST", "127.0.0.1:9999", "tok"},
	} {
		if rec := call(c.method, c.host, c.token); rec.Code == 200 {
			t.Errorf("%+v must be refused", c)
		}
	}
}
