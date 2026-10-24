package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/ai"
	"github.com/Karthik-099/TERRAGUARD/internal/stats"
	"github.com/Karthik-099/TERRAGUARD/web"
)

// runServe self-hosts the web app plus a small API. AI keys stay server-side
// in .env, so a team shares one configuration and browsers never see keys.
func runServe(args []string) error {
	fset := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fset.String("addr", "127.0.0.1:8080", "listen address (use 0.0.0.0:8080 in containers)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	token := os.Getenv("TERRAGUARD_SERVER_TOKEN")
	if host, _, _ := net.SplitHostPort(*addr); host != "127.0.0.1" && host != "localhost" && host != "::1" && token == "" {
		log.Printf("warning: listening on %s without TERRAGUARD_SERVER_TOKEN; anyone who can reach it can use your AI keys", *addr)
	}
	if _, err := fs.Stat(web.FS, "terraguard.wasm"); err != nil {
		log.Printf("warning: terraguard.wasm is not embedded; run `make web` before building, or use the Docker image")
	}
	srv := &http.Server{Addr: *addr, Handler: newServer(token), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 120 * time.Second}
	log.Printf("TerraGuard %s on http://%s  (AI route: %d step(s)%s)", engine.Version, *addr, len(ai.Route()), map[bool]string{true: ", local-only"}[ai.LocalOnly()])
	return srv.ListenAndServe()
}

func newServer(token string) http.Handler {
	mux := http.NewServeMux()
	st := stats.New()
	mux.Handle("/", http.FileServerFS(web.FS))

	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		var route []string
		for _, s := range ai.Route() {
			route = append(route, s.String())
		}
		writeJSON(w, 200, map[string]any{"version": engine.Version, "auth": token != "",
			"ai": map[string]any{"enabled": len(route) > 0, "local_only": ai.LocalOnly(), "route": route}})
	})

	api := func(h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if token != "" && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(token)) != 1 {
				writeJSON(w, 401, map[string]string{"error": "missing or invalid server token"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
			st.Begin()
			defer st.End()
			h(w, r)
		}
	}

	mux.HandleFunc("POST /api/ai/chat", api(func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("POST /api/scan", api(func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /api/stats/hit", func(w http.ResponseWriter, r *http.Request) {
		var h stats.Hit
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&h); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid hit"})
			return
		}
		st.Record(h)
		w.WriteHeader(204)
	})

	mux.HandleFunc("POST /api/fix", api(func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	return mux
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

// reportUsage sends anonymous counts to TERRAGUARD_TELEMETRY_URL when the user
// opts in. It is fire-and-forget with a short timeout so it never slows CI.
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
