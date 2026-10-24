package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func clearEnv(t *testing.T) {
	for _, k := range []string{"GROQ_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "TERRAGUARD_AI_ROUTE",
		"TERRAGUARD_AI_PROVIDER", "AI_PROVIDER", "TERRAGUARD_AI_MODEL", "TERRAGUARD_OLLAMA_URL", "OLLAMA_URL", "TERRAGUARD_AI_BASE_URL", "TERRAGUARD_AI_KEY", "TERRAGUARD_AI_LOCAL_ONLY"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestDotenvUppercasesAndKeepsExisting(t *testing.T) {
	clearEnv(t)
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("# c\ngroq_api_key=gsk_1  # inline\nexport OPENROUTER_API_KEY=\"sk-or\"\nGEMINI_API_KEY=\n"), 0o600)
	t.Setenv("TERRAGUARD_AI_MODEL", "keep")
	if err := LoadDotenv(p); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GROQ_API_KEY") != "gsk_1" || os.Getenv("OPENROUTER_API_KEY") != "sk-or" || os.Getenv("TERRAGUARD_AI_MODEL") != "keep" {
		t.Fatalf("got groq=%q or=%q", os.Getenv("GROQ_API_KEY"), os.Getenv("OPENROUTER_API_KEY"))
	}
	t.Cleanup(func() { os.Unsetenv("GROQ_API_KEY"); os.Unsetenv("OPENROUTER_API_KEY") })
}

func TestRouteOrderAndOverrides(t *testing.T) {
	clearEnv(t)
	t.Setenv("GROQ_API_KEY", "g")
	t.Setenv("OPENROUTER_API_KEY", "o")
	r := Route()
	if r[0].Provider.Name != "groq" || r[len(r)-1].Provider.Name != "openrouter" {
		t.Fatalf("default order: %v", r)
	}
	t.Setenv("TERRAGUARD_AI_PROVIDER", "openrouter")
	if Route()[0].Provider.Name != "openrouter" {
		t.Fatal("preferred provider not first")
	}
	t.Setenv("TERRAGUARD_AI_ROUTE", "openrouter:x/y,groq,gemini")
	r = Route()
	if r[0].String() != "openrouter:x/y" || r[1].Provider.Name != "groq" || len(r) != 1+3 {
		t.Fatalf("explicit route: %v", r) // gemini has no key, so it's dropped
	}
}

func TestFallbackAcrossModelsAndProviders(t *testing.T) {
	clearEnv(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct{ Model string }
		_ = jsonDecode(r, &body)
		switch body.Model {
		case "bad-key":
			http.Error(w, `{"error":"invalid key"}`, 401)
		case "rate":
			http.Error(w, `{"error":"slow down"}`, 429)
		default:
			w.Write([]byte(`{"choices":[{"message":{"content":"ok from ` + body.Model + `"}}]}`))
		}
	}))
	defer srv.Close()
	t.Setenv("TERRAGUARD_AI_BASE_URL", srv.URL)
	t.Setenv("TERRAGUARD_AI_ROUTE", "custom:rate,custom:good")
	res, err := Chat(context.Background(), []Message{{Role: "user", Content: "hi"}})
	if err != nil || res.Model != "good" || len(res.Attempts) != 1 || !strings.Contains(res.Attempts[0], "429") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	calls.Store(0)
	t.Setenv("TERRAGUARD_AI_ROUTE", "custom:bad-key,custom:good")
	if _, err := Chat(context.Background(), nil); err == nil || calls.Load() != 1 {
		t.Fatalf("a 401 must skip the rest of that provider (calls=%d)", calls.Load())
	}
}

func jsonDecode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

func TestLocalOnlyNeverRoutesToCloud(t *testing.T) {
	clearEnv(t)
	t.Setenv("GROQ_API_KEY", "g")
	t.Setenv("TERRAGUARD_OLLAMA_URL", "http://localhost:11434/v1")
	t.Setenv("TERRAGUARD_AI_LOCAL_ONLY", "true")
	for _, s := range Route() {
		if s.Provider.Name != "ollama" {
			t.Fatalf("cloud provider in local-only route: %v", s)
		}
	}
	if len(Route()) == 0 {
		t.Fatal("ollama missing")
	}
}

func TestRedactNeverLeaksKeys(t *testing.T) {
	clearEnv(t)
	t.Setenv("GROQ_API_KEY", "gsk_supersecretvalue123")
	for _, in := range []string{"bad key gsk_supersecretvalue123", "Incorrect API key provided: sk-proj-abcdEFGH1234", "Authorization: Bearer abc.def", "key AIzaSyA1234567890abcdefghijklmnop"} {
		if out := Redact(in); strings.Contains(out, "supersecret") || strings.Contains(out, "abcdEFGH") || strings.Contains(out, "abc.def") || strings.Contains(out, "AIzaSy") {
			t.Errorf("leaked: %q", out)
		}
	}
}
