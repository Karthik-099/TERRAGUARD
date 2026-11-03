package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
	"github.com/Karthik-099/TERRAGUARD/internal/stats"
	"github.com/Karthik-099/TERRAGUARD/web"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runServe: web app plus API; AI keys stay on the server.
func runServe(args []string) error {
	fset := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fset.String("addr", "127.0.0.1:8080", "listen address (use 0.0.0.0:8080 in containers)")
	auditPath := fset.String("audit-log", os.Getenv("TERRAGUARD_AUDIT_LOG"), "append a JSON line per API call (metadata only, never code)")
	policyPath := fset.String("admission-policy", "", "policy file for the Kubernetes admission webhook at /api/k8s/validate")
	tlsCert := fset.String("tls-cert", "", "serve HTTPS with this certificate (the Kubernetes API server calls webhooks over HTTPS only)")
	tlsKey := fset.String("tls-key", "", "private key for --tls-cert")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if *policyPath != "" {
		text, err := resolvePolicyFile(*policyPath)
		if err != nil {
			return fmt.Errorf("admission policy: %w", err)
		}
		admissionPolicy = text
	}
	token := os.Getenv("TERRAGUARD_SERVER_TOKEN")
	if host, _, _ := net.SplitHostPort(*addr); host != "127.0.0.1" && host != "localhost" && host != "::1" && token == "" {
		log.Printf("warning: listening on %s without TERRAGUARD_SERVER_TOKEN; anyone who can reach it can use your AI keys", *addr)
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
	srv := &http.Server{Addr: *addr, Handler: newServerWith(token, audit), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	log.Printf("TerraGuard %s on http://%s  (AI route: %d step(s)%s)", engine.Version, *addr, len(ai.Route()), map[bool]string{true: ", local-only"}[ai.LocalOnly()])
	if *tlsCert != "" || *tlsKey != "" {
		return srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	}
	return srv.ListenAndServe()
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
	mux := http.NewServeMux()
	mcpServer := newMCPServer(false)
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
		rep := engine.Scan(in)
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
		changed, errs := engine.FixAll(in)
		st.Record(stats.Hit{Surface: "api", Fixes: len(changed)})
		msgs := []string{}
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		writeJSON(w, 200, map[string]any{"files": changed, "errors": msgs})
	}))

	// Remote MCP: token-protected, inline files only.
	remote := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	mux.Handle("/mcp", api("/mcp", apiLimit, remote.ServeHTTP))

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
	return secureHeaders(mux)
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
	if url == "" {
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
