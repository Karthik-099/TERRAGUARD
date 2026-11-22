package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/acme/autocert"
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
	if resp, _ := http.Get(srv.URL + "/metrics"); resp.StatusCode != 401 {
		t.Fatalf("metrics without token: status = %d", resp.StatusCode)
	}
	// No directory listings and no Go source from the embedded site.
	for _, path := range []string{"/assets/", "/embed.go"} {
		if resp, _ := http.Get(srv.URL + path); resp.StatusCode != 404 {
			t.Errorf("GET %s: status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestHSTSOnlyOverHTTPS(t *testing.T) {
	h := newServer("")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS sent over plain HTTP")
	}
	t.Setenv("TERRAGUARD_TRUST_PROXY", "true")
	r := httptest.NewRequest("GET", "/healthz", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("no HSTS behind a TLS-terminating proxy")
	}
}

func TestClientIPUsesProxyAppendedAddress(t *testing.T) {
	t.Setenv("TERRAGUARD_TRUST_PROXY", "true")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 10.0.0.7")
	if got := clientIP(r); got != "10.0.0.7" {
		t.Fatalf("clientIP = %q, want the proxy-appended 10.0.0.7", got)
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
	first, second, third := l.allow("a", now), l.allow("a", now), l.allow("a", now)
	if !first || !second || third {
		t.Fatal("third request inside the burst must be refused")
	}
	if !l.allow("b", now) {
		t.Fatal("clients are limited independently")
	}
	if !l.allow("a", now.Add(31*time.Second)) {
		t.Fatal("tokens must refill over time")
	}
}

func TestServerRefusesCrossSiteAndRebinding(t *testing.T) {
	h := loopbackOnly(newServer(""))
	call := func(host, site string) int {
		req := httptest.NewRequest("POST", "/api/scan", strings.NewReader(`{}`))
		req.Host = host
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := call("127.0.0.1:8080", ""); c != 200 {
		t.Fatalf("curl-style call: %d", c)
	}
	if c := call("localhost:8080", "same-origin"); c != 200 {
		t.Fatalf("the web app itself: %d", c)
	}
	if c := call("localhost:8080", "cross-site"); c != 403 {
		t.Errorf("cross-site POST (CSRF) must be refused: %d", c)
	}
	if c := call("attacker.example:8080", ""); c != 403 {
		t.Errorf("rebound host name must be refused: %d", c)
	}
	for in, want := range map[string]bool{"127.0.0.1:80": true, "[::1]:80": true, "localhost": true, "LOCALHOST:1": true, "127.0.0.2": true,
		"0.0.0.0:8080": false, ":8080": false, "localhost.attacker.example": false, "10.0.0.1:80": false} {
		if loopbackHost(in) != want {
			t.Errorf("loopbackHost(%q) != %v", in, want)
		}
	}
}

func TestMCPSecretLink(t *testing.T) {
	key := "Zq3vR8tLw2NcY7pK4mXa9HbE6sJd1FgU5oTiV0yW"
	audit := &syncBuffer{}
	srv := httptest.NewServer(newServerOpts(serverOpts{mcpKey: key, exposed: true, audit: audit}))
	defer srv.Close()
	ctx := context.Background()
	connect := func(path string) (*mcp.ClientSession, error) {
		c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
		return c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + path, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	}
	cs, err := connect("/mcp/" + key)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "explain_rule", Arguments: map[string]any{"id": "TG-AWS-S3-001"}})
	cs.Close()
	if err != nil || res.IsError {
		t.Fatalf("explain_rule over the secret link: %v %+v", err, res)
	}
	for _, path := range []string{"/mcp/" + strings.Repeat("x", 40), "/mcp/" + key[:39]} {
		r, _ := http.Post(srv.URL+path, "application/json", strings.NewReader(`{}`))
		if r.StatusCode != 404 {
			t.Errorf("wrong key %s: status %d, want 404", path, r.StatusCode)
		}
	}
	// Exposed with no token: bare /mcp is refused, not just warned about.
	if r, _ := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(`{}`)); r.StatusCode != 403 {
		t.Errorf("bare /mcp without a token: %d", r.StatusCode)
	}
	for i := 0; i < 100 && strings.Count(audit.String(), `"route":"/mcp/`) < 4; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(audit.String(), key) || strings.Contains(audit.String(), "xxxxxxxx") || strings.Count(audit.String(), `"route":"/mcp/`) < 4 {
		t.Fatalf("audit must redact the key: %s", audit.String())
	}
	// No key configured: the secret path does not exist.
	h := newServerOpts(serverOpts{token: "t"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/mcp/"+key, strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatalf("secret link without a key: %d", w.Code)
	}
}

func TestMCPKeyStorage(t *testing.T) {
	t.Setenv("TERRAGUARD_MCP_KEY", "short")
	if _, err := mcpKey(false, ""); err == nil {
		t.Fatal("a short TERRAGUARD_MCP_KEY was accepted")
	}
	t.Setenv("TERRAGUARD_MCP_KEY", "")
	if k, _ := mcpKey(false, t.TempDir()); k != "" {
		t.Fatal("no key without --domain or TERRAGUARD_MCP_KEY")
	}
	dir := filepath.Join(t.TempDir(), "certs")
	k1, err := mcpKey(true, dir)
	if err != nil || len(k1) < 32 {
		t.Fatalf("key %d chars, %v", len(k1), err)
	}
	if st, _ := os.Stat(mcpKeyPath(dir)); st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", st.Mode().Perm())
	}
	if k2, _ := mcpKey(true, dir); k2 != k1 {
		t.Fatal("the stored key must be reused")
	}
	if err := runServe([]string{"--rotate-mcp-key", "--cert-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if k3, _ := mcpKey(true, dir); k3 == k1 {
		t.Fatal("rotate did not replace the key")
	}
	t.Setenv("TERRAGUARD_OFFLINE", "true")
	if err := runServe([]string{"--domain", "tg.example.com", "--cert-dir", dir}); err == nil || !strings.Contains(err.Error(), "TERRAGUARD_OFFLINE") {
		t.Fatalf("--domain with offline mode: %v", err)
	}
}

func TestHTTPSRedirectAndRequireHTTPS(t *testing.T) {
	// The :80 handler --domain uses; no certificate is requested for a redirect.
	m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist("tg.example.com")}
	w := httptest.NewRecorder()
	m.HTTPHandler(nil).ServeHTTP(w, httptest.NewRequest("GET", "http://tg.example.com/api/config?x=1", nil))
	if w.Code != 302 || w.Header().Get("Location") != "https://tg.example.com/api/config?x=1" {
		t.Fatalf("redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
	h := requireHTTPS(newServer(""))
	call := func(remote string, tls bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/healthz", nil)
		r.RemoteAddr = remote
		if tls {
			r.TLS = &tlsState
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if c := call("203.0.113.5:4000", false).Code; c != 403 {
		t.Errorf("plain HTTP from outside: %d", c)
	}
	if c := call("127.0.0.1:4000", false).Code; c != 200 {
		t.Errorf("plain HTTP from loopback: %d", c)
	}
	if w := call("203.0.113.5:4000", true); w.Code != 200 || w.Header().Get("Strict-Transport-Security") == "" {
		t.Errorf("HTTPS: %d, HSTS %q", w.Code, w.Header().Get("Strict-Transport-Security"))
	}
	t.Setenv("TERRAGUARD_TRUST_PROXY", "true")
	r := httptest.NewRequest("GET", "/healthz", nil)
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("X-Forwarded-Proto", "http")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("plain HTTP through a local proxy: %d", w.Code)
	}
}

var tlsState = tls.ConnectionState{}

func TestScanGateBusyAndTimeout(t *testing.T) {
	g := newScanGate(1, 50*time.Millisecond)
	release := make(chan struct{})
	started := make(chan struct{})
	go g.run(context.Background(), func() { close(started); <-release })
	<-started
	srv := httptest.NewServer(newServerOpts(serverOpts{gate: g}))
	defer srv.Close()
	r, err := http.Post(srv.URL+"/api/scan", "application/json", strings.NewReader(`{"files":{"a.tf":""}}`))
	if err != nil || r.StatusCode != 503 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("busy: %v %v %q", err, r.StatusCode, r.Header.Get("Retry-After"))
	}
	close(release)
	for i := 0; i < 100 && len(g.slots) > 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if err := g.run(context.Background(), func() { time.Sleep(200 * time.Millisecond) }); err != errScanTimeout {
		t.Fatalf("timeout: %v", err)
	}
	if err := g.run(context.Background(), func() {}); err != errBusy {
		t.Fatalf("a timed-out scan must keep its slot until it ends: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := g.run(context.Background(), func() {}); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
}
