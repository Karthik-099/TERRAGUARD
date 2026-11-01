package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// Run tasks for HCP Terraform and Terraform Enterprise: scan the plan, report back.
// https://developer.hashicorp.com/terraform/enterprise/api-docs/run-tasks/run-tasks-integration

type runTaskRequest struct {
	AccessToken  string `json:"access_token"`
	Stage        string `json:"stage"`
	PlanJSONURL  string `json:"plan_json_api_url"`
	CallbackURL  string `json:"task_result_callback_url"`
	RunID        string `json:"run_id"`
	Workspace    string `json:"workspace_name"`
	Organization string `json:"organization_name"`
}

type runTask struct {
	key    []byte       // HMAC key configured on the run task
	host   string       // the only host we will call, e.g. app.terraform.io
	config string       // optional .terraguard.yml applied to every run
	client *http.Client // HTTPS only; redirects stay on the platform's domain
	slots  chan struct{}
}

// newRunTask returns nil when TERRAGUARD_RUN_TASK_HMAC_KEY is unset (disabled).
func newRunTask() *runTask {
	key := os.Getenv("TERRAGUARD_RUN_TASK_HMAC_KEY")
	if key == "" {
		return nil
	}
	host := os.Getenv("TERRAGUARD_TFC_HOST")
	if host == "" {
		host = "app.terraform.io"
	}
	cfg, _ := readOptional(os.Getenv("TERRAGUARD_RUN_TASK_CONFIG"))
	rt := &runTask{key: []byte(key), host: host, config: cfg, slots: make(chan struct{}, 4)}
	rt.client = &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || !rt.allowed(r.URL) {
			return errors.New("redirect outside the Terraform platform")
		}
		return nil
	}}
	return rt
}

// allowed keeps outbound calls on the platform, so a forged payload can't reach other hosts.
func (rt *runTask) allowed(u *url.URL) bool {
	if u.Scheme != "https" {
		return false
	}
	domain := strings.TrimPrefix(rt.host, "app.")
	return u.Host == rt.host || u.Host == domain || strings.HasSuffix(u.Host, "."+domain)
}

func (rt *runTask) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "body too large"})
		return
	}
	mac := hmac.New(sha512.New, rt.key)
	mac.Write(body)
	sig, _ := hex.DecodeString(r.Header.Get("X-Tfc-Task-Signature"))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		writeJSON(w, 401, map[string]string{"error": "invalid signature"})
		return
	}
	var req runTaskRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid payload"})
		return
	}
	if req.AccessToken == "test-token" { // the platform's verification request
		w.WriteHeader(200)
		return
	}
	cb, err1 := url.Parse(req.CallbackURL)
	plan, err2 := url.Parse(req.PlanJSONURL)
	if err1 != nil || err2 != nil || !rt.allowed(cb) || (req.PlanJSONURL != "" && !rt.allowed(plan)) {
		writeJSON(w, 400, map[string]string{"error": "callback or plan URL is not on " + rt.host})
		return
	}
	select {
	case rt.slots <- struct{}{}:
	default:
		writeJSON(w, 503, map[string]string{"error": "busy"})
		return
	}
	w.WriteHeader(200) // the platform waits for the callback, not this response
	go func() {
		defer func() { <-rt.slots }()
		status, msg := rt.check(req)
		if err := rt.report(req, status, msg); err != nil {
			log.Printf("run task %s: callback failed: %v", req.RunID, err)
		}
	}()
}

// check scans the run's plan and returns passed or failed with a short summary.
func (rt *runTask) check(req runTaskRequest) (status, msg string) {
	if req.Stage != "post_plan" || req.PlanJSONURL == "" {
		return "passed", "TerraGuard checks plans; configure the run task for the post-plan stage."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	hreq, _ := http.NewRequestWithContext(ctx, "GET", req.PlanJSONURL, nil)
	hreq.Header.Set("Authorization", "Bearer "+req.AccessToken)
	resp, err := rt.client.Do(hreq)
	if err != nil {
		return "failed", "Could not download the plan: " + err.Error()
	}
	defer resp.Body.Close()
	planJSON, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil || resp.StatusCode != 200 {
		return "failed", fmt.Sprintf("Could not download the plan (HTTP %d).", resp.StatusCode)
	}
	rep := engine.Scan(engine.Input{Plan: string(planJSON), Config: rt.config})
	return runTaskSummary(rep)
}

func runTaskSummary(rep *engine.Report) (status, msg string) {
	status = "passed"
	if !rep.Passed {
		status = "failed"
	}
	active := 0
	var top []string
	for _, f := range rep.Findings {
		if f.Waived {
			continue
		}
		active++
		if len(top) < 3 {
			top = append(top, fmt.Sprintf("%s %s (%s)", f.Severity, f.Title, f.Resource))
		}
	}
	msg = fmt.Sprintf("TerraGuard %s: grade %s, %d active finding(s).", status, rep.Grade, active)
	if len(top) > 0 {
		msg += " Top: " + strings.Join(top, "; ") + "."
	}
	if len(msg) > 500 {
		msg = msg[:497] + "..."
	}
	return status, msg
}

func (rt *runTask) report(req runTaskRequest, status, msg string) error {
	body, _ := json.Marshal(map[string]any{"data": map[string]any{"type": "task-results",
		"attributes": map[string]string{"status": status, "message": msg}}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hreq, _ := http.NewRequestWithContext(ctx, "PATCH", req.CallbackURL, bytes.NewReader(body))
	hreq.Header.Set("Authorization", "Bearer "+req.AccessToken)
	hreq.Header.Set("Content-Type", "application/vnd.api+json")
	resp, err := rt.client.Do(hreq)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
