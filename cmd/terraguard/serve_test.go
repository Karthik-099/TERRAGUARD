package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerNeverExposesKeysAndCountsScans(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "gsk_do_not_leak_123456")
	srv := httptest.NewServer(newServer(""))
	defer srv.Close()

	get := func(path string) string {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if cfg := get("/api/config"); strings.Contains(cfg, "gsk_") || !strings.Contains(cfg, `"enabled":true`) {
		t.Fatalf("config = %s", cfg)
	}
	resp, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(`{"files":{"a.tf":"resource \"aws_db_instance\" \"x\" { publicly_accessible = true }"}}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("scan: %v %v", err, resp.Status)
	}
	var snap struct {
		Today struct{ Scans, Files, Resources int } `json:"today"`
	}
	json.Unmarshal([]byte(get("/api/stats")), &snap)
	if snap.Today.Scans != 1 || snap.Today.Files != 1 || snap.Today.Resources != 1 {
		t.Fatalf("stats = %+v", snap)
	}
	if body := get("/api/stats"); strings.Contains(body, "a.tf") || strings.Contains(body, "publicly_accessible") {
		t.Fatal("stats must never contain code or file names")
	}
}

func TestServerTokenRequired(t *testing.T) {
	srv := httptest.NewServer(newServer("s3cret"))
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(`{}`))
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/scan", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Fatalf("with token status = %d", resp.StatusCode)
	}
}
