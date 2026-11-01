package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunTaskScansPlanAndReportsBack(t *testing.T) {
	plan, err := os.ReadFile("../../examples/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan string, 1)
	tfc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer run-token" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/plan":
			w.Write(plan)
		case r.Method == "PATCH" && r.URL.Path == "/callback":
			b, _ := io.ReadAll(r.Body)
			results <- string(b)
		}
	}))
	defer tfc.Close()
	host := strings.TrimPrefix(tfc.URL, "https://")
	t.Setenv("TERRAGUARD_RUN_TASK_HMAC_KEY", "k3y")
	t.Setenv("TERRAGUARD_TFC_HOST", host)
	rt := newRunTask()
	rt.client.Transport = tfc.Client().Transport

	post := func(payload map[string]string, key string) int {
		body, _ := json.Marshal(payload)
		mac := hmac.New(sha512.New, []byte(key))
		mac.Write(body)
		req := httptest.NewRequest("POST", "/api/run-task", strings.NewReader(string(body)))
		req.Header.Set("X-Tfc-Task-Signature", hex.EncodeToString(mac.Sum(nil)))
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		return w.Code
	}
	run := map[string]string{"access_token": "run-token", "stage": "post_plan", "run_id": "run-1",
		"plan_json_api_url": tfc.URL + "/plan", "task_result_callback_url": tfc.URL + "/callback"}

	if code := post(run, "wrong"); code != 401 {
		t.Fatalf("bad signature: status %d", code)
	}
	if code := post(map[string]string{"access_token": "test-token"}, "k3y"); code != 200 {
		t.Fatalf("verification request: status %d", code)
	}
	evil := map[string]string{"access_token": "run-token", "stage": "post_plan", "plan_json_api_url": "https://169.254.169.254/latest", "task_result_callback_url": tfc.URL + "/callback"}
	if code := post(evil, "k3y"); code != 400 {
		t.Fatalf("plan URL off the platform was accepted: status %d", code)
	}
	if code := post(run, "k3y"); code != 200 {
		t.Fatalf("run: status %d", code)
	}
	select {
	case got := <-results:
		if !strings.Contains(got, `"status":"failed"`) || !strings.Contains(got, "TerraGuard failed") {
			t.Fatalf("unexpected callback: %s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no callback")
	}
}
