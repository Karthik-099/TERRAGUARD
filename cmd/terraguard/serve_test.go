package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

// syncBuffer is safe to read while the server writes to it.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestServerHardening(t *testing.T) {
	audit := &syncBuffer{}
	srv := httptest.NewServer(newServerWith("", audit))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	body := `{"files":{"main.tf":"resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }"}}`
	if r, _ := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(body)); r.StatusCode != 200 {
		t.Fatalf("scan status %d", r.StatusCode)
	}
	// The record is written after the response is sent.
	for i := 0; i < 100 && !strings.Contains(audit.String(), "/api/scan"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(audit.String(), `"route":"/api/scan"`) || strings.Contains(audit.String(), "public-read") {
		t.Fatalf("audit must record metadata but never code: %s", audit.String())
	}
	m, _ := http.Get(srv.URL + "/metrics")
	b, _ := io.ReadAll(m.Body)
	for _, want := range []string{`terraguard_http_requests_total{route="/api/scan",code="200"} 1`, "terraguard_scans_total 1", "terraguard_resources_scanned_total 1"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("metrics missing %q:\n%s", want, b)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	l := newLimiter(2)
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) || l.allow("a", now) {
		t.Fatal("third request inside the burst must be refused")
	}
	if !l.allow("b", now) {
		t.Fatal("clients are limited independently")
	}
	if !l.allow("a", now.Add(31*time.Second)) {
		t.Fatal("tokens must refill over time")
	}
}
