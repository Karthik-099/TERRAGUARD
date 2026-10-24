// Package ai routes chat requests across free LLM providers with automatic
// fallback. It is advisory only: nothing in TerraGuard gates on its output.
package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Result struct {
	Text     string   `json:"text"`
	Provider string   `json:"provider"`
	Model    string   `json:"model"`
	Attempts []string `json:"attempts,omitempty"` // failures before the answer
}

type Provider struct {
	Name   string
	Base   string // OpenAI-compatible base URL
	KeyEnv string
	Models []string // tried in order
	NoKey  bool     // local servers (Ollama, LM Studio, vLLM)
}

// Providers in default fallback order: free tiers only (no paid APIs), local last.
func Providers() []Provider {
	ollama := firstEnv("TERRAGUARD_OLLAMA_URL", "OLLAMA_URL")
	ps := []Provider{
		{Name: "groq", Base: "https://api.groq.com/openai/v1", KeyEnv: "GROQ_API_KEY",
			Models: []string{"openai/gpt-oss-120b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b"}},
		{Name: "openrouter", Base: "https://openrouter.ai/api/v1", KeyEnv: "OPENROUTER_API_KEY",
			// Free slugs churn monthly; openrouter/free is the last-resort router to any live free model.
			Models: []string{"nvidia/nemotron-3-super-120b-a12b:free", "google/gemma-4-31b-it:free", "openrouter/free"}},
		{Name: "gemini", Base: "https://generativelanguage.googleapis.com/v1beta/openai", KeyEnv: "GEMINI_API_KEY",
			Models: []string{"gemini-2.5-flash", "gemini-2.5-flash-lite"}},
	}
	if ollama != "" {
		ps = append(ps, Provider{Name: "ollama", Base: strings.TrimSuffix(ollama, "/"), NoKey: true,
			Models: []string{orDefault(os.Getenv("TERRAGUARD_OLLAMA_MODEL"), "llama3.2")}})
	}
	if base := os.Getenv("TERRAGUARD_AI_BASE_URL"); base != "" {
		ps = append(ps, Provider{Name: "custom", Base: strings.TrimSuffix(base, "/"), KeyEnv: "TERRAGUARD_AI_KEY",
			NoKey: os.Getenv("TERRAGUARD_AI_KEY") == "", Models: []string{orDefault(os.Getenv("TERRAGUARD_AI_MODEL"), "default")}})
	}
	return ps
}

// Step is one (provider, model) attempt in the route.
type Step struct {
	Provider Provider
	Model    string
}

func (s Step) String() string { return s.Provider.Name + ":" + s.Model }

// Route builds the fallback chain from configured providers.
//
//	TERRAGUARD_AI_ROUTE="groq:openai/gpt-oss-120b,openrouter,gemini:gemini-2.5-flash"  explicit chain
//	TERRAGUARD_AI_PROVIDER=openrouter   put this provider first, keep the rest as fallback
//	TERRAGUARD_AI_MODEL=...             override the first model of the preferred provider
func Route() []Step {
	all := map[string]Provider{}
	var order []string
	localOnly := LocalOnly()
	for _, p := range Providers() {
		if localOnly && p.Name != "ollama" && p.Name != "custom" {
			continue // private mode: never send code to a hosted API
		}
		if p.NoKey || os.Getenv(p.KeyEnv) != "" {
			all[p.Name] = p
			order = append(order, p.Name)
		}
	}
	var steps []Step
	if route := os.Getenv("TERRAGUARD_AI_ROUTE"); route != "" {
		for _, part := range strings.Split(route, ",") {
			name, model, _ := strings.Cut(strings.TrimSpace(part), ":")
			p, ok := all[name]
			if !ok {
				continue
			}
			if model != "" {
				steps = append(steps, Step{p, model})
				continue
			}
			for _, m := range p.Models {
				steps = append(steps, Step{p, m})
			}
		}
		return steps
	}
	pref := firstEnv("TERRAGUARD_AI_PROVIDER", "AI_PROVIDER")
	if _, ok := all[pref]; ok {
		rest := []string{pref}
		for _, n := range order {
			if n != pref {
				rest = append(rest, n)
			}
		}
		order = rest
	}
	for i, n := range order {
		p := all[n]
		models := p.Models
		if m := os.Getenv("TERRAGUARD_AI_MODEL"); m != "" && i == 0 && p.Name != "custom" {
			models = append([]string{m}, models...)
		}
		for _, m := range models {
			steps = append(steps, Step{p, m})
		}
	}
	return steps
}

// LocalOnly reports TERRAGUARD_AI_LOCAL_ONLY=true: only Ollama / custom local endpoints are used.
func LocalOnly() bool {
	v := strings.ToLower(os.Getenv("TERRAGUARD_AI_LOCAL_ONLY"))
	return v == "1" || v == "true" || v == "yes"
}

var ErrNoProvider = errors.New("no AI provider configured: set GROQ_API_KEY, OPENROUTER_API_KEY or GEMINI_API_KEY (or TERRAGUARD_OLLAMA_URL for a local model) in .env")

type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.msg) }

// Chat walks the route until one step answers. Rate limits, outages, timeouts
// and unknown models fall through to the next step; a rejected key skips the
// rest of that provider's models.
func Chat(ctx context.Context, msgs []Message) (*Result, error) {
	steps := Route()
	if len(steps) == 0 {
		return nil, ErrNoProvider
	}
	res := &Result{}
	badKey := map[string]bool{}
	for _, s := range steps {
		if badKey[s.Provider.Name] {
			continue
		}
		text, err := call(ctx, s, msgs)
		if err == nil {
			res.Text, res.Provider, res.Model = text, s.Provider.Name, s.Model
			return res, nil
		}
		res.Attempts = append(res.Attempts, s.String()+" → "+Redact(err.Error()))
		var he *httpError
		if errors.As(err, &he) && (he.status == 401 || he.status == 403) {
			badKey[s.Provider.Name] = true
		}
		if ctx.Err() != nil {
			break
		}
	}
	return res, fmt.Errorf("all AI routes failed:\n  %s", strings.Join(res.Attempts, "\n  "))
}

func call(ctx context.Context, s Step, msgs []Message) (string, error) {
	body, _ := json.Marshal(map[string]any{"model": s.Model, "messages": msgs, "temperature": 0.2})
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", s.Provider.Base+"/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv(s.Provider.KeyEnv); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if s.Provider.Name == "openrouter" {
		req.Header.Set("HTTP-Referer", "https://github.com/Karthik-099/TERRAGUARD")
		req.Header.Set("X-Title", "TerraGuard")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(out.Error))
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", &httpError{resp.StatusCode, Redact(msg)}
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		return "", errors.New("empty response")
	}
	return out.Choices[0].Message.Content, nil
}

// LoadDotenv reads KEY=VALUE lines into the environment without overriding
// variables that are already set. Keys are upper-cased (groq_api_key works).
func LoadDotenv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !ok {
			continue
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 && !strings.HasPrefix(v, `"`) && !strings.HasPrefix(v, "'") {
			v = strings.TrimSpace(v[:i]) // inline comment
		}
		v = strings.Trim(v, `"'`)
		if _, set := os.LookupEnv(k); !set && v != "" {
			os.Setenv(k, v)
		}
	}
	return sc.Err()
}

var keyLike = regexp.MustCompile(`(sk-[A-Za-z0-9_\-*]{8,}|gsk_[A-Za-z0-9]{8,}|AIza[0-9A-Za-z_\-]{20,}|sk-or-v1-[a-f0-9*]{8,}|Bearer\s+\S+)`)

// Redact masks anything that looks like an API key so provider error
// messages can be shown in logs, PR comments and the UI safely.
func Redact(s string) string {
	for _, p := range Providers() {
		if k := os.Getenv(p.KeyEnv); len(k) >= 8 {
			s = strings.ReplaceAll(s, k, "[redacted]")
		}
	}
	return keyLike.ReplaceAllString(s, "[redacted]")
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return strings.ToLower(v)
		}
	}
	return ""
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
