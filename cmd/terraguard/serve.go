package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
	"github.com/Karthik-099/TERRAGUARD/internal/stats"
	"github.com/Karthik-099/TERRAGUARD/web"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/acme/autocert"
)

// runServe: web app plus API; AI keys stay on the server.
func runServe(args []string) error {
	fset := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fset.String("addr", "127.0.0.1:8080", "listen address (use 0.0.0.0:8080 in containers)")
	auditPath := fset.String("audit-log", os.Getenv("TERRAGUARD_AUDIT_LOG"), "append a JSON line per API call (metadata only, never code)")
	policyPath := fset.String("admission-policy", "", "policy file for the Kubernetes admission webhook at /api/k8s/validate")
	tlsCert := fset.String("tls-cert", "", "serve HTTPS with this certificate (the Kubernetes API server calls webhooks over HTTPS only)")
	tlsKey := fset.String("tls-key", "", "private key for --tls-cert")
	domain := fset.String("domain", "", "get a Let's Encrypt certificate for this host name; serves HTTPS on :443 and redirects :80")
	certDir := fset.String("cert-dir", defaultCertDir(), "certificate cache and stored MCP key for --domain")
	httpsOnly := fset.Bool("https-only", false, "refuse plain-HTTP requests that are not from loopback")
	rotateKey := fset.Bool("rotate-mcp-key", false, "replace the stored MCP secret-link key in --cert-dir and exit")
	scanTimeout := fset.Duration("scan-timeout", 30*time.Second, "longest time one scan may run in the API and remote MCP")
	maxScans := fset.Int("max-scans", runtime.GOMAXPROCS(0), "scans that may run at once; more get 503 with Retry-After")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if *rotateKey {
		if os.Getenv("TERRAGUARD_MCP_KEY") != "" {
			return errors.New("TERRAGUARD_MCP_KEY is set and takes precedence; change it there instead")
		}
		if _, err := writeMCPKey(*certDir); err != nil {
			return err
		}
		fmt.Printf("New MCP key stored in %s. Restart terraguard serve, then run `terraguard connect claude-ai --url https://<host> --show-secret` for the new link; the old link stops working.\n", mcpKeyPath(*certDir))
		return nil
	}
	if *policyPath != "" {
		text, err := resolvePolicyFile(*policyPath)
		if err != nil {
			return fmt.Errorf("admission policy: %w", err)
		}
		admissionPolicy = text
	}
	if *domain != "" {
		if os.Getenv("TERRAGUARD_OFFLINE") == "true" {
			return errors.New("--domain needs Let's Encrypt over the internet, but TERRAGUARD_OFFLINE=true forbids outside requests; use --tls-cert and --tls-key instead")
		}
		if *tlsCert != "" || *tlsKey != "" {
			return errors.New("use either --domain or --tls-cert/--tls-key, not both")
		}
		*addr = ":443"
	}
	key, err := mcpKey(*domain != "", *certDir)
	if err != nil {
		return err
	}
	token := os.Getenv("TERRAGUARD_SERVER_TOKEN")
	exposed := !loopbackHost(*addr) || os.Getenv("TERRAGUARD_TRUST_PROXY") == "true"
	if exposed && token == "" {
		log.Printf("warning: listening on %s without TERRAGUARD_SERVER_TOKEN; anyone who can reach it can use your AI keys", *addr)
		if key == "" {
			log.Printf("MCP is off: set TERRAGUARD_SERVER_TOKEN or TERRAGUARD_MCP_KEY to serve /mcp beyond loopback")
		}
	}
	if _, err := fs.Stat(web.FS, "terraguard.wasm"); err != nil {
		log.Printf("warning: terraguard.wasm is not embedded; run `make web` before building, or use the Docker image")
	}
	var audit io.Writer
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("audit log: %w", err)
		}
		defer f.Close()
		audit = f
	}
	handler := newServerOpts(serverOpts{token: token, mcpKey: key, exposed: exposed, audit: audit, gate: newScanGate(*maxScans, *scanTimeout)})
	if loopbackHost(*addr) && token == "" && os.Getenv("TERRAGUARD_TRUST_PROXY") != "true" {
		handler = loopbackOnly(handler) // no token: a rebound DNS name must not reach the API from a web page
	}
	if *httpsOnly || *domain != "" {
		handler = requireHTTPS(handler)
	}
	srv := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	scheme, host := "http", *addr
	if *domain != "" || *tlsCert != "" {
		scheme = "https"
	}
	if *domain != "" {
		host = *domain
	}
	log.Printf("TerraGuard %s on %s://%s  (AI route: %d step(s)%s)", engine.Version, scheme, host, len(ai.Route()), map[bool]string{true: ", local-only"}[ai.LocalOnly()])
	if key != "" {
		log.Printf("MCP secret link is on; print it with `terraguard connect claude-ai --url %s://%s --show-secret`", scheme, host)
	}
	if *domain != "" {
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(*domain), Cache: autocert.DirCache(*certDir)}
		srv.TLSConfig = m.TLSConfig()
		// :80 answers the HTTP-01 challenge and redirects everything else to HTTPS.
		plain := &http.Server{Addr: ":80", Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
		go func() { log.Printf("http redirect on :80: %v", plain.ListenAndServe()) }()
		return srv.ListenAndServeTLS("", "")
	}
	if *tlsCert != "" || *tlsKey != "" {
		return srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	}
	return srv.ListenAndServe()
}

func defaultCertDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "terraguard", "autocert")
}

func mcpKeyPath(dir string) string { return filepath.Join(dir, "mcp-key") }

var mcpKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`)

// mcpKey: TERRAGUARD_MCP_KEY, else (with --domain) the stored key, created on first use.
func mcpKey(domain bool, dir string) (string, error) {
	if k := os.Getenv("TERRAGUARD_MCP_KEY"); k != "" {
		if !mcpKeyRE.MatchString(k) {
			return "", errors.New("TERRAGUARD_MCP_KEY must be at least 32 random characters from A-Z, a-z, 0-9, - and _")
		}
		return k, nil
	}
	if !domain {
		return "", nil
	}
	b, err := os.ReadFile(mcpKeyPath(dir))
	if err == nil && mcpKeyRE.Match(bytes.TrimSpace(b)) {
		return string(bytes.TrimSpace(b)), nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("mcp key: %w", err)
	}
	return writeMCPKey(dir)
}

// writeMCPKey stores a new 256-bit key readable by the owner only.
func writeMCPKey(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mcp key: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	k := base64.RawURLEncoding.EncodeToString(raw)
	tmp := mcpKeyPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, []byte(k+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("mcp key: %w", err)
	}
	if err := os.Rename(tmp, mcpKeyPath(dir)); err != nil {
		return "", fmt.Errorf("mcp key: %w", err)
	}
	return k, nil
}

// requireHTTPS refuses plain HTTP unless it comes straight from loopback.
func requireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := ""
		if os.Getenv("TERRAGUARD_TRUST_PROXY") == "true" {
			proto = r.Header.Get("X-Forwarded-Proto")
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if r.TLS == nil && proto != "https" && (proto != "" || !loopbackHost(host)) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "HTTPS required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// scanGate bounds concurrent engine work and how long a caller waits for it.
type scanGate struct {
	slots   chan struct{}
	timeout time.Duration
}

var (
	errBusy        = errors.New("server busy: too many scans in progress; retry in a few seconds")
	errScanTimeout = errors.New("scan timed out; send fewer or smaller files")
)

func newScanGate(n int, timeout time.Duration) *scanGate {
	return &scanGate{slots: make(chan struct{}, max(n, 1)), timeout: timeout}
}

// run calls fn with a free slot. On timeout it returns at once, but the slot
// stays taken until fn ends (Go cannot stop it), so CPU use stays bounded.
// fn's results must not be read after an error.
func (g *scanGate) run(ctx context.Context, fn func()) error {
	if g == nil {
		fn()
		return nil
	}
	select {
	case g.slots <- struct{}{}:
	default:
		return errBusy
	}
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() { <-g.slots }()
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("scan failed: %v", p)
			}
		}()
		fn()
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errScanTimeout
	}
}

// gatedHTTP runs fn under the gate and writes 503 or 504 when it cannot.
func gatedHTTP(g *scanGate, w http.ResponseWriter, r *http.Request, fn func()) bool {
	switch err := g.run(r.Context(), fn); {
	case err == nil:
		return true
	case errors.Is(err, errBusy):
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
	case errors.Is(err, errScanTimeout):
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return false
}

// admissionPolicy is the policy text the admission webhook applies.
var admissionPolicy string

func resolvePolicyFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	text, err := resolvePolicy(string(b), filepath.Dir(p))
	if err != nil {
		return "", err
	}
	_, err = engine.ParseConfig(text)
	return text, err
}

func newServer(token string) http.Handler { return newServerWith(token, nil) }

func newServerWith(token string, audit io.Writer) http.Handler {
	return newServerOpts(serverOpts{token: token, audit: audit, gate: newScanGate(runtime.GOMAXPROCS(0), 30*time.Second)})
}

type serverOpts struct {
	token   string // bearer token for the API and /mcp
	mcpKey  string // secret for /mcp/<key>; empty turns the secret link off
	exposed bool   // reachable beyond loopback: /mcp then needs the token
	audit   io.Writer
	gate    *scanGate
}

func newServerOpts(o serverOpts) http.Handler {
	token, audit, gate := o.token, o.audit, o.gate
	mux := http.NewServeMux()
	mcpServer := newMCPServer(false, gate)
	st := stats.New()
	met := newMetrics()
	apiLimit, aiLimit := newLimiter(120), newLimiter(20)
	if audit != nil {
		audit = &lockedWriter{w: audit}
	}
	mux.Handle("/", staticFiles(web.FS))

	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		var route []string
		for _, s := range ai.Route() {
			route = append(route, s.String())
		}
		writeJSON(w, 200, map[string]any{"version": engine.Version, "auth": token != "",
			"ai": map[string]any{"enabled": len(route) > 0, "local_only": ai.LocalOnly(), "route": route}})
	})

	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		if token != "" && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
			writeJSON(w, 401, map[string]string{"error": "missing or invalid server token"})
			return false
		}
		return true
	}
	api := func(route string, lim *limiter, h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
		return observe(route, lim, met, audit, func(w http.ResponseWriter, r *http.Request) {
			if !authorized(w, r) {
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
			st.Begin()
			defer st.End()
			h(w, r)
		})
	}

	mux.HandleFunc("POST /api/ai/chat", api("/api/ai/chat", aiLimit, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []ai.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Messages) == 0 {
			writeJSON(w, 400, map[string]string{"error": "expected {messages:[...]}"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 110*time.Second)
		defer cancel()
		res, err := ai.Chat(ctx, req.Messages)
		st.Record(stats.Hit{Surface: "web", AI: 1})
		if err != nil {
			writeJSON(w, 502, map[string]any{"error": err.Error(), "attempts": res})
			return
		}
		writeJSON(w, 200, res)
	}))

	mux.HandleFunc("POST /api/scan", api("/api/scan", apiLimit, func(w http.ResponseWriter, r *http.Request) {
		var in engine.Input
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		t0 := time.Now()
		var rep *engine.Report
		if !gatedHTTP(gate, w, r, func() { rep = engine.Scan(in) }) {
			return
		}
		st.Record(scanHit("api", rep, int(time.Since(t0).Milliseconds())))
		writeJSON(w, 200, rep)
	}))

	// Public, anonymous counters for the dashboard (numbers only).
	mux.HandleFunc("GET /api/stats", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, st.Snapshot()) })
	mux.HandleFunc("POST /api/stats/hit", observe("/api/stats/hit", apiLimit, met, nil, func(w http.ResponseWriter, r *http.Request) {
		var h stats.Hit
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&h); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid hit"})
			return
		}
		st.Record(h)
		w.WriteHeader(204)
	}))

	mux.HandleFunc("POST /api/fix", api("/api/fix", apiLimit, func(w http.ResponseWriter, r *http.Request) {
		var in engine.Input
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
		var changed map[string]string
		var errs []error
		if !gatedHTTP(gate, w, r, func() { changed, errs = engine.FixAll(in) }) {
			return
		}
		st.Record(stats.Hit{Surface: "api", Fixes: len(changed)})
		msgs := []string{}
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		writeJSON(w, 200, map[string]any{"files": changed, "errors": msgs})
	}))

	// Remote MCP: inline files only. /mcp takes the bearer token; /mcp/<key> is
	// the secret link for clients that cannot send headers. Beyond loopback,
	// MCP without either secret is refused.
	remote := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	if o.exposed && token == "" {
		mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "MCP needs TERRAGUARD_SERVER_TOKEN (or the TERRAGUARD_MCP_KEY secret link) when the server is reachable beyond loopback"})
		})
	} else {
		mux.Handle("/mcp", api("/mcp", apiLimit, remote.ServeHTTP))
	}
	// The route name, not the path, goes to metrics and the audit log, so the key never does.
	mux.Handle("/mcp/{key}", observe("/mcp/<key>", apiLimit, met, audit, func(w http.ResponseWriter, r *http.Request) {
		if o.mcpKey == "" || subtle.ConstantTimeCompare([]byte(r.PathValue("key")), []byte(o.mcpKey)) != 1 {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
		st.Begin()
		defer st.End()
		remote.ServeHTTP(w, r)
	}))

	// HCP Terraform / Terraform Enterprise run task; authenticated by HMAC, not the token.
	if rt := newRunTask(); rt != nil {
		mux.Handle("POST /api/run-task", observe("/api/run-task", apiLimit, met, audit, rt.ServeHTTP))
	}

	mux.HandleFunc("POST /api/k8s/validate", api("/api/k8s/validate", apiLimit, admissionHandler(admissionPolicy)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	// Metrics need the token when one is set (Prometheus: authorization.credentials).
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		writeMetrics(w, met, st)
	})
	// Browsers send Sec-Fetch-Site/Origin: a cross-site page cannot POST to the API (CSRF);
	// curl, agents, Kubernetes and run tasks send neither and pass.
	return secureHeaders(http.NewCrossOriginProtection().Handler(mux))
}

// loopbackHost reports whether host[:port] names this machine by a loopback
// name or address. DNS rebinding arrives with the attacker's host name instead.
func loopbackHost(hostport string) bool {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// loopbackOnly refuses requests whose Host header is not a loopback name.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden host; set TERRAGUARD_SERVER_TOKEN to serve other host names"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// staticFiles: no directory listings, no Go source.
func staticFiles(fsys fs.FS) http.Handler {
	files := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") || strings.HasSuffix(r.URL.Path, ".go") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// scanHit converts a report to anonymous counts: rule IDs and totals only.
func scanHit(surface string, rep *engine.Report, ms int) stats.Hit {
	h := stats.Hit{Surface: surface, Scans: 1, Files: rep.Stats.Files, Resources: rep.Stats.Resources, Ms: ms, Rules: map[string]int{}}
	for _, f := range rep.Findings {
		if !f.Waived {
			h.Findings++
			h.Rules[f.RuleID]++
		}
	}
	return h
}

// reportUsage is opt-in and fire-and-forget, so it never slows CI.
func reportUsage(rep *engine.Report, ms int) {
	url := os.Getenv("TERRAGUARD_TELEMETRY_URL")
	if url == "" || os.Getenv("TERRAGUARD_OFFLINE") == "true" {
		return
	}
	surface := "cli"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		surface = "action"
	}
	body, _ := json.Marshal(scanHit(surface, rep, ms))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimSuffix(url, "/")+"/hit", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}
