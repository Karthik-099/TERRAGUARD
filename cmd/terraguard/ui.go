package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// runUI opens the workspace on this machine with a folder loaded from disk:
// the desktop experience without a desktop framework. The server listens on
// loopback only, the file API needs a one-time token and the right Host
// header (against DNS rebinding), and it only reads.
func runUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:0", "loopback address to listen on (port 0 picks a free one)")
	noBrowser := fs.Bool("no-browser", false, "print the address instead of opening a browser")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || !(host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return errors.New("ui: --addr must be a loopback address")
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	token := hex.EncodeToString(b)
	listen := ln.Addr().String()
	srv := &http.Server{Handler: uiHandler(newServer(""), paths, token, listen), ReadHeaderTimeout: 10 * time.Second}
	url := fmt.Sprintf("http://%s/#/app?local=%s", listen, token)
	fmt.Printf("TerraGuard workspace for %s at %s (Ctrl+C to stop)\n", strings.Join(paths, ", "), url)
	if !*noBrowser {
		openBrowser(url)
	}
	return srv.Serve(ln)
}

// uiHandler adds GET /api/local/files to the normal server.
func uiHandler(next http.Handler, paths []string, token, listen string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/local/files" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet || r.Host != listen {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-TerraGuard-Local")), []byte(token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or wrong token"})
			return
		}
		files, err := loadFiles(paths)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"root": strings.Join(paths, ", "), "files": files})
	})
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Println("open this address in a browser:", url)
	}
}
