package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer lets the test read the server's output while the server
// goroutine writes it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// validKey returns a base64 key that satisfies the 32-byte requirement.
func validKey(t *testing.T) string {
	t.Helper()
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(key[:])
}

// setValidEnv pins a complete, valid configuration so a test only has to
// change the one thing it is about. External variables are cleared rather
// than assumed absent: a developer's shell must not change the outcome.
func setValidEnv(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	t.Setenv("NEXT_PANEL_ENV", "development")
	t.Setenv("NEXT_PANEL_LISTEN", "127.0.0.1:0")
	t.Setenv("NEXT_PANEL_BASE_URL", "http://localhost:8080")
	t.Setenv("NEXT_PANEL_EXTERNAL_SCHEME", "http")
	t.Setenv("NEXT_PANEL_DATA_DIR", dataDir)
	t.Setenv("NEXT_PANEL_LOG_LEVEL", "INFO")
	t.Setenv("NEXT_PANEL_LOG_FORMAT", "text")
	t.Setenv("NEXT_PANEL_DB_DRIVER", "sqlite")
	t.Setenv("NEXT_PANEL_DB_DSN", "")
	t.Setenv("NEXT_PANEL_ENCRYPTION_KEY", validKey(t))
	t.Setenv("NEXT_PANEL_ENCRYPTION_KEY_ID", "1")
	t.Setenv("NEXT_PANEL_TRUSTED_PROXIES", "")
	t.Setenv("NEXT_PANEL_ALLOWED_ORIGINS", "")
	return dataDir
}

func TestRunRefusesInvalidEncryptionKey(t *testing.T) {
	setValidEnv(t)
	t.Setenv("NEXT_PANEL_ENCRYPTION_KEY", "too-short")

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "NEXT_PANEL_ENCRYPTION_KEY") {
		t.Fatalf("stderr should name the offending variable, got %q", msg)
	}
	if strings.Contains(msg, "too-short") {
		t.Fatalf("stderr must not echo the configured secret, got %q", msg)
	}
}

func TestRunRefusesInvalidListenAddress(t *testing.T) {
	setValidEnv(t)
	t.Setenv("NEXT_PANEL_LISTEN", "not-a-host-port")

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "NEXT_PANEL_LISTEN") {
		t.Fatalf("stderr should name the offending variable, got %q", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"frobnicate"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCryptoGenerateKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"crypto", "generate-key"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", code, stderr.String())
	}
	first := strings.TrimSpace(stdout.String())
	raw, err := base64.StdEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("output is not base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("key length = %d, want 32", len(raw))
	}
}

func TestRunVersionPrintsJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var body struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &body); err != nil {
		t.Fatalf("version output is not JSON: %v", err)
	}
	if body.Version == "" {
		t.Fatal("version is empty")
	}
}

var listenRe = regexp.MustCompile(`listen=([^\s"]+)`)

// TestServeStartsServesAndShutsDown exercises the whole process: startup
// checks, migrations, the three endpoints, and a clean shutdown on context
// cancellation (Design Spec §33.5, §38 phase 1 exit criteria).
func TestServeStartsServesAndShutsDown(t *testing.T) {
	dataDir := setValidEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out, errOut := &syncBuffer{}, &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil, out, errOut) }()

	addr := waitForListen(t, out, done)

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/health", `"status":"ok"`},
		{"/ready", `"status":"ready"`},
	} {
		resp, body := get(t, "http://"+addr+tc.path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, body = %s", tc.path, resp.StatusCode, body)
		}
		if !strings.Contains(body, tc.want) {
			t.Fatalf("GET %s body = %s, want it to contain %s", tc.path, body, tc.want)
		}
		if resp.Header.Get("X-Request-ID") == "" {
			t.Fatalf("GET %s did not set X-Request-ID", tc.path)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("GET %s content-type = %q", tc.path, ct)
		}
		_ = resp.Body.Close()
	}

	resp, body := get(t, "http://"+addr+"/version")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /version status = %d, body = %s", resp.StatusCode, body)
	}
	var info struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("/version body is not JSON: %v (%s)", err, body)
	}
	_ = resp.Body.Close()
	for _, leak := range []string{dataDir, "NEXT_PANEL", "sqlite", "://"} {
		if strings.Contains(body, leak) {
			t.Fatalf("/version leaks configuration %q: %s", leak, body)
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("serve exit code = %d, want 0 (stderr: %s)", code, errOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not shut down after the context was cancelled")
	}
}

// waitForListen blocks until the process reports the address it bound.
func waitForListen(t *testing.T, out *syncBuffer, done chan int) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m := listenRe.FindStringSubmatch(out.String()); m != nil {
			return m[1]
		}
		select {
		case code := <-done:
			t.Fatalf("process exited early with code %d: %s", code, out.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("process never reported a listen address: %s", out.String())
	return ""
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp, string(body)
}

// TestCheckDataDirRejectsFileInPlaceOfDirectory keeps the startup check honest
// for the case an operator actually hits: a data directory that is a file.
func TestCheckDataDirRejectsFileInPlaceOfDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkDataDir(file); err == nil {
		t.Fatal("checkDataDir accepted a regular file as the data directory")
	}
}
