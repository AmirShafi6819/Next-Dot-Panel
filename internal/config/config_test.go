package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// validKey is a syntactically valid 32-byte key. It is not a secret and is
// never used outside tests.
var validKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// setEnv applies the given environment for the duration of the test.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func minimalEnv() map[string]string {
	return map[string]string{"NEXT_PANEL_ENCRYPTION_KEY": validKey}
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t, minimalEnv())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Env != EnvDevelopment {
		t.Errorf("Env = %q, want %q", cfg.Env, EnvDevelopment)
	}
	if cfg.Database.Driver != DriverSQLite {
		t.Errorf("Driver = %q, want %q", cfg.Database.Driver, DriverSQLite)
	}
	if cfg.Database.MaxConns != 1 {
		// SQLite must be pinned to a single writer (Design Spec §7.4).
		t.Errorf("SQLite MaxConns = %d, want 1", cfg.Database.MaxConns)
	}
	if cfg.Database.SQLitePath == "" {
		t.Error("SQLitePath should default to a path under DataDir")
	}
	if cfg.Features.LocalExecutionEnabled {
		t.Error("local execution must default to disabled")
	}
	if cfg.Features.ContainersEnabled {
		t.Error("containers must default to disabled")
	}
	if cfg.Features.ServicesEnabled {
		t.Error("systemd control must default to disabled")
	}
	if cfg.Security.EncryptionKeyID != 1 {
		t.Errorf("EncryptionKeyID = %d, want 1", cfg.Security.EncryptionKeyID)
	}
	if cfg.Timeouts.Metrics != 2*cfg.Features.MetricInterval {
		t.Errorf("Metrics timeout = %s, want 2x interval (%s)", cfg.Timeouts.Metrics, 2*cfg.Features.MetricInterval)
	}
	if len(cfg.Security.AllowedOrigins) == 0 {
		t.Error("AllowedOrigins should default to the BaseURL origin")
	}
}

func TestLoadRejectsMissingEncryptionKey(t *testing.T) {
	// Explicitly blank rather than relying on absence, so the test is
	// deterministic if the developer has a real key exported.
	setEnv(t, map[string]string{"NEXT_PANEL_ENCRYPTION_KEY": " "})

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when the encryption key is missing")
	}
	if !strings.Contains(err.Error(), "NEXT_PANEL_ENCRYPTION_KEY is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsBadEncryptionKey(t *testing.T) {
	for name, key := range map[string]string{
		"not base64":      "!!!nope!!!",
		"wrong length 16": base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		"wrong length 64": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64))),
	} {
		t.Run(name, func(t *testing.T) {
			setEnv(t, map[string]string{"NEXT_PANEL_ENCRYPTION_KEY": key})
			_, err := Load()
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "NEXT_PANEL_ENCRYPTION_KEY") {
				t.Fatalf("error does not name the offending variable: %v", err)
			}
		})
	}
}

func TestProductionRequiresHTTPS(t *testing.T) {
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY":  validKey,
		"NEXT_PANEL_ENV":             "production",
		"NEXT_PANEL_EXTERNAL_SCHEME": "http",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("production with http scheme must be refused")
	}
	if !strings.Contains(err.Error(), "insecure cookies") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProductionHTTPSAccepted(t *testing.T) {
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY":  validKey,
		"NEXT_PANEL_ENV":             "production",
		"NEXT_PANEL_EXTERNAL_SCHEME": "https",
		"NEXT_PANEL_DB_DRIVER":       "postgres",
		"NEXT_PANEL_DB_DSN":          "postgres://user:pw@localhost:5432/db",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.App.IsProduction() {
		t.Error("IsProduction() = false in production mode")
	}
}

func TestPostgresRequiresDSN(t *testing.T) {
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY": validKey,
		"NEXT_PANEL_DB_DRIVER":      "postgres",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when postgres has no DSN")
	}
	if !strings.Contains(err.Error(), "NEXT_PANEL_DB_DSN is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionIdleMustNotExceedLifetime(t *testing.T) {
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY":   validKey,
		"NEXT_PANEL_SESSION_LIFETIME": "1h",
		"NEXT_PANEL_SESSION_IDLE":     "2h",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when idle timeout exceeds session lifetime")
	}
	if !strings.Contains(err.Error(), "must not exceed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMetricIntervalFloor(t *testing.T) {
	// Sub-second collection over SSH would saturate the connection.
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY":  validKey,
		"NEXT_PANEL_METRIC_INTERVAL": "100ms",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for a sub-second metric interval")
	}
	if !strings.Contains(err.Error(), "at least 1s") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrustedProxies(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		setEnv(t, map[string]string{
			"NEXT_PANEL_ENCRYPTION_KEY":  validKey,
			"NEXT_PANEL_TRUSTED_PROXIES": "127.0.0.1,10.0.0.0/8,::1",
		})
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.Security.TrustedProxies) != 3 {
			t.Fatalf("got %d trusted proxies, want 3", len(cfg.Security.TrustedProxies))
		}
		if !cfg.IsTrustedProxy([]byte{127, 0, 0, 1}) {
			t.Error("127.0.0.1 should be trusted")
		}
		if !cfg.IsTrustedProxy([]byte{10, 1, 2, 3}) {
			t.Error("10.1.2.3 should be inside 10.0.0.0/8")
		}
		if cfg.IsTrustedProxy([]byte{8, 8, 8, 8}) {
			t.Error("8.8.8.8 must not be trusted")
		}
	})

	t.Run("invalid entry is rejected", func(t *testing.T) {
		setEnv(t, map[string]string{
			"NEXT_PANEL_ENCRYPTION_KEY":  validKey,
			"NEXT_PANEL_TRUSTED_PROXIES": "not-an-ip",
		})
		if _, err := Load(); err == nil {
			t.Fatal("expected an error for an invalid trusted proxy entry")
		}
	})

	t.Run("empty means nothing is trusted", func(t *testing.T) {
		setEnv(t, minimalEnv())
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.IsTrustedProxy([]byte{127, 0, 0, 1}) {
			t.Error("with no configured proxies, nothing may be trusted")
		}
	})
}

func TestBootstrapDisabledSkipsCredentialValidation(t *testing.T) {
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY":     validKey,
		"NEXT_PANEL_BOOTSTRAP_ADMIN":    "false",
		"NEXT_PANEL_BOOTSTRAP_PASSWORD": "",
	})

	if _, err := Load(); err != nil {
		t.Fatalf("disabling bootstrap should not require a bootstrap password: %v", err)
	}
}

func TestLoadAggregatesAllProblems(t *testing.T) {
	// A single pass should report every problem, not stop at the first.
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY": "",
		"NEXT_PANEL_ENV":            "nonsense",
		"NEXT_PANEL_LOG_LEVEL":      "VERBOSE",
		"NEXT_PANEL_DB_DRIVER":      "mysql",
		"NEXT_PANEL_SESSION_IDLE":   "-5m",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("expected errors")
	}
	verr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(verr.Problems) < 4 {
		t.Fatalf("expected several aggregated problems, got %d: %v", len(verr.Problems), verr.Problems)
	}
	for _, want := range []string{"ENV", "LOG_LEVEL", "DB_DRIVER", "ENCRYPTION_KEY", "SESSION_IDLE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("aggregated error does not mention %s:\n%s", want, err)
		}
	}
}

func TestPreviousKeysParsing(t *testing.T) {
	setEnv(t, map[string]string{
		"NEXT_PANEL_ENCRYPTION_KEY":           validKey,
		"NEXT_PANEL_ENCRYPTION_PREVIOUS_KEYS": "0:" + validKey + ", 2:" + validKey + ",bogus,3:" + validKey,
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// id 0 is out of range and "bogus" has no separator, so both are dropped.
	if len(cfg.Security.PreviousKeys) != 2 {
		t.Fatalf("got %d previous keys, want 2: %v", len(cfg.Security.PreviousKeys), cfg.Security.PreviousKeys)
	}
	if _, ok := cfg.Security.PreviousKeys[2]; !ok {
		t.Error("key id 2 should be present")
	}
	if _, ok := cfg.Security.PreviousKeys[0]; ok {
		t.Error("key id 0 must be rejected")
	}
}

func TestDataDirDefaultAndOverride(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		setEnv(t, minimalEnv())
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !strings.HasSuffix(cfg.Database.SQLitePath, "nextpanel.db") {
			t.Errorf("SQLitePath = %q", cfg.Database.SQLitePath)
		}
	})

	t.Run("explicit DSN wins", func(t *testing.T) {
		setEnv(t, map[string]string{
			"NEXT_PANEL_ENCRYPTION_KEY": validKey,
			"NEXT_PANEL_DB_DSN":         "/tmp/custom.db",
		})
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Database.SQLitePath != "/tmp/custom.db" {
			t.Errorf("SQLitePath = %q, want /tmp/custom.db", cfg.Database.SQLitePath)
		}
	})
}

func TestTimeoutsAreSane(t *testing.T) {
	setEnv(t, minimalEnv())
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for name, d := range map[string]time.Duration{
		"SSHConnect":    cfg.Timeouts.SSHConnect,
		"SSHAuth":       cfg.Timeouts.SSHAuth,
		"Command":       cfg.Timeouts.Command,
		"DatabaseQuery": cfg.Timeouts.DatabaseQuery,
		"HTTPRequest":   cfg.Timeouts.HTTPRequest,
		"TerminalIdle":  cfg.Timeouts.TerminalIdle,
		"SSHKeepAlive":  cfg.Timeouts.SSHKeepAlive,
	} {
		if d <= 0 {
			t.Errorf("%s timeout is %s; every network operation must be bounded", name, d)
		}
	}
}
