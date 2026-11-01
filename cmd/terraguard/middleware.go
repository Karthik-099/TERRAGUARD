package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
	"github.com/Karthik-099/TERRAGUARD/internal/stats"
)

// secureHeaders sets defensive headers on every response. The page also
// carries a Content-Security-Policy meta tag; frame-ancestors must be a header.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		next.ServeHTTP(w, r)
	})
}

// limiter is a per-client token bucket for the API. It keeps one entry per
// active client and forgets idle ones, so memory stays bounded.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	clients map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute int) *limiter {
	return &limiter{rate: float64(perMinute) / 60, burst: float64(perMinute), clients: map[string]*bucket{}}
}

func (l *limiter) allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.clients) > 10000 {
		for k, b := range l.clients {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.clients, k)
			}
		}
	}
	b := l.clients[client]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.clients[client] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientIP uses the socket address unless the server sits behind a trusted
// proxy (TERRAGUARD_TRUST_PROXY=true), where X-Forwarded-For is authoritative.
func clientIP(r *http.Request) string {
	if os.Getenv("TERRAGUARD_TRUST_PROXY") == "true" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ip, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(ip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// user returns the identity asserted by a trusted SSO proxy, if any.
func user(r *http.Request) string {
	if os.Getenv("TERRAGUARD_TRUST_PROXY") != "true" {
		return ""
	}
	for _, h := range []string{"Cf-Access-Authenticated-User-Email", "X-Auth-Request-Email", "X-Forwarded-Email", "X-Forwarded-User"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// metrics counts requests per route and status for Prometheus.
type metrics struct {
	mu       sync.Mutex
	requests map[string]int     // "route|code"
	seconds  map[string]float64 // route -> total duration
}

func newMetrics() *metrics {
	return &metrics{requests: map[string]int{}, seconds: map[string]float64{}}
}

// lockedWriter serializes audit records from every route onto one writer,
// so concurrent requests never interleave lines.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// observe wraps an API route: rate limit, measure, and append an audit record.
// Audit records hold metadata only, never request bodies.
func observe(route string, lim *limiter, m *metrics, audit io.Writer, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		ip := clientIP(r)
		if lim != nil && !lim.allow(ip, start) {
			sw.Header().Set("Retry-After", "10")
			writeJSON(sw, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		} else {
			next(sw, r)
		}
		elapsed := time.Since(start)
		m.mu.Lock()
		m.requests[fmt.Sprintf("%s|%d", route, sw.status)]++
		m.seconds[route] += elapsed.Seconds()
		m.mu.Unlock()
		if audit != nil {
			line, _ := json.Marshal(map[string]any{"time": start.UTC().Format(time.RFC3339Nano), "route": route, "method": r.Method,
				"status": sw.status, "duration_ms": elapsed.Milliseconds(), "client": ip, "user": user(r)})
			_, _ = audit.Write(append(line, '\n'))
		}
	}
}

// writeMetrics renders the Prometheus text exposition format.
func writeMetrics(w io.Writer, m *metrics, st *stats.Store) {
	snap := st.Snapshot()
	fmt.Fprintf(w, "# HELP terraguard_build_info Build information.\n# TYPE terraguard_build_info gauge\nterraguard_build_info{version=%q} 1\n", engine.Version)
	m.mu.Lock()
	keys := make([]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintln(w, "# HELP terraguard_http_requests_total API requests by route and status.\n# TYPE terraguard_http_requests_total counter")
	counts := map[string]int{}
	for _, k := range keys {
		route, code, _ := strings.Cut(k, "|")
		fmt.Fprintf(w, "terraguard_http_requests_total{route=%q,code=%q} %d\n", route, code, m.requests[k])
		counts[route] += m.requests[k]
	}
	routes := make([]string, 0, len(m.seconds))
	for r := range m.seconds {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	fmt.Fprintln(w, "# HELP terraguard_http_request_duration_seconds Time spent serving API requests.\n# TYPE terraguard_http_request_duration_seconds summary")
	for _, r := range routes {
		fmt.Fprintf(w, "terraguard_http_request_duration_seconds_sum{route=%q} %g\nterraguard_http_request_duration_seconds_count{route=%q} %d\n", r, m.seconds[r], r, counts[r])
	}
	m.mu.Unlock()
	for _, c := range []struct {
		name, help string
		v          int
	}{
		{"terraguard_scans_total", "Evaluations performed.", snap.Total.Scans},
		{"terraguard_files_scanned_total", "Terraform files evaluated.", snap.Total.Files},
		{"terraguard_resources_scanned_total", "Resources analyzed.", snap.Total.Resources},
		{"terraguard_findings_total", "Active findings reported.", snap.Total.Findings},
		{"terraguard_fixes_total", "Fixes applied.", snap.Total.Fixes},
		{"terraguard_ai_requests_total", "AI assistant requests.", snap.Total.AI},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", c.name, c.help, c.name, c.name, c.v)
	}
	fmt.Fprintf(w, "# HELP terraguard_inflight_requests API requests in progress.\n# TYPE terraguard_inflight_requests gauge\nterraguard_inflight_requests %d\n", snap.Running)
}
