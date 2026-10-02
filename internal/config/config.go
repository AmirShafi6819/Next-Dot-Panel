// Package config loads and validates Next.Panel's runtime configuration.
//
// Configuration comes from environment variables only. Validation fails fast
// at startup (Design Spec §33.5): a process that cannot encrypt credentials or
// reach its database must not start and pretend to work.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment names.
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// Database drives.
const (
	DriverPostgres = "postgres"
	DriverSQLite   = "sqlite"
)

// Config is the fully validated runtime configuration.
type Config struct {
	Env      string
	App      App
	Database Database
	Security Security
	Limits   Limits
	Features Features
	Timeouts Timeouts
}

// App holds process-level settings.
type App struct {
	Env            string
	ListenAddr     string
	BaseURL        string
	ExternalScheme string // "http" or "https" — drives Secure cookies and HSTS
	Timezone       string

	DataDir   string
	LogLevel  string
	LogFormat string // "json" or "text"
}

// IsProduction reports whether the process runs in production mode.
func (a App) IsProduction() bool { return a.Env == EnvProduction }

// Database holds storage settings.
type Database struct {
	Driver   string // "postgres" or "sqlite"
	DSN      string
	MaxConns int
	// SQLitePath is the resolved database file path when Driver == sqlite.
	SQLitePath string
}

// Security holds credential, session, and origin settings.
type Security struct {
	EncryptionKey   string // base64, 32 bytes
	EncryptionKeyID uint8
	PreviousKeys    map[uint8]string

	SessionLifetime time.Duration
	SessionIdle     time.Duration
	ReauthWindow    time.Duration

	TrustedProxies []*net.IPNet
	AllowedOrigins []string

	BootstrapAdminEnabled bool
	BootstrapUsername     string
	BootstrapPassword     string

	RateLimitAuth      int
	RateLimitAuthWnd   time.Duration
	MaxLoginFailures   int
	LoginLockoutWindow time.Duration
}

// Limits holds resource caps (Design Spec §57).
type Limits struct {
	MaxUploadBytes        int64
	MaxConcurrentUploads  int
	MaxTerminalsPerUser   int
	MaxTerminalsPerServer int
	MaxTerminalsGlobal    int
	MaxConnPerServer      int
	MaxConnPerUser        int
	MaxFileListEntries    int
	MaxPreviewBytes       int64
	MaxArchiveEntries     int
	MaxArchiveTotalBytes  int64
	MaxArchiveFileBytes   int64
	MaxArchiveRatio       int
	MaxCommandOutputBytes int64
	MetricsPointBudget    int
}

// Features gates privileged subsystems. All default to false so a default
// installation cannot reach host-privileged capabilities (Design Spec §13.4).
type Features struct {
	LocalExecutionEnabled bool
	LocalFileRoots        []string
	ContainersEnabled     bool
	ServicesEnabled       bool

	MetricInterval        time.Duration
	MetricRetentionRaw    time.Duration
	MetricRetention5m     time.Duration
	MetricRetention1h     time.Duration
	AuditRetention        time.Duration
	LoginHistoryRetention time.Duration
	AppLogRetention       time.Duration
	BackupRetention       int
	BackupDir             string

	SchedulerEnabled bool
	WorkersEnabled   bool
	WorkerCount      int
}

// Timeouts holds per-operation deadlines (Design Spec §26.6).
type Timeouts struct {
	SSHConnect       time.Duration
	SSHAuth          time.Duration
	Command          time.Duration
	Metrics          time.Duration
	DatabaseQuery    time.Duration
	HTTPRequest      time.Duration
	FileIdle         time.Duration
	TerminalIdle     time.Duration
	SSHKeepAlive     time.Duration
	SSHIdle          time.Duration
	SSHMaxReconnects int
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		Env: envString("NEXT_PANEL_ENV", EnvDevelopment),
		App: App{
			Env:            envString("NEXT_PANEL_ENV", EnvDevelopment),
			ListenAddr:     envString("NEXT_PANEL_LISTEN", ":8080"),
			BaseURL:        envString("NEXT_PANEL_BASE_URL", "http://localhost:8080"),
			ExternalScheme: strings.ToLower(envString("NEXT_PANEL_EXTERNAL_SCHEME", "http")),
			Timezone:       envString("NEXT_PANEL_TIMEZONE", "UTC"),
			DataDir:        envString("NEXT_PANEL_DATA_DIR", "./data"),
			LogLevel:       strings.ToUpper(envString("NEXT_PANEL_LOG_LEVEL", "INFO")),
			LogFormat:      strings.ToLower(envString("NEXT_PANEL_LOG_FORMAT", "text")),
		},
		Database: Database{
			Driver:   strings.ToLower(envString("NEXT_PANEL_DB_DRIVER", DriverSQLite)),
			DSN:      envString("NEXT_PANEL_DB_DSN", ""),
			MaxConns: envInt("NEXT_PANEL_DB_MAX_CONNS", 10),
		},
		Security: Security{
			EncryptionKey:   envString("NEXT_PANEL_ENCRYPTION_KEY", ""),
			EncryptionKeyID: uint8(envInt("NEXT_PANEL_ENCRYPTION_KEY_ID", 1)),

			SessionLifetime: envDuration("NEXT_PANEL_SESSION_LIFETIME", 12*time.Hour),
			SessionIdle:     envDuration("NEXT_PANEL_SESSION_IDLE", 2*time.Hour),
			ReauthWindow:    envDuration("NEXT_PANEL_REAUTH_WINDOW", 5*time.Minute),

			BootstrapAdminEnabled: envBool("NEXT_PANEL_BOOTSTRAP_ADMIN", true),
			BootstrapUsername:     envString("NEXT_PANEL_BOOTSTRAP_USERNAME", "admin"),
			BootstrapPassword:     envString("NEXT_PANEL_BOOTSTRAP_PASSWORD", "123456"),

			RateLimitAuth:      envInt("NEXT_PANEL_RATE_LIMIT_AUTH", 10),
			RateLimitAuthWnd:   envDuration("NEXT_PANEL_RATE_LIMIT_AUTH_WINDOW", 15*time.Minute),
			MaxLoginFailures:   envInt("NEXT_PANEL_MAX_LOGIN_FAILURES", 5),
			LoginLockoutWindow: envDuration("NEXT_PANEL_LOGIN_LOCKOUT_WINDOW", 15*time.Minute),
		},
		Limits: Limits{
			MaxUploadBytes:        envInt64("NEXT_PANEL_MAX_UPLOAD_BYTES", 2<<30), // 2 GiB
			MaxConcurrentUploads:  envInt("NEXT_PANEL_MAX_CONCURRENT_UPLOADS", 3),
			MaxTerminalsPerUser:   envInt("NEXT_PANEL_MAX_TERMINALS_PER_USER", 5),
			MaxTerminalsPerServer: envInt("NEXT_PANEL_MAX_TERMINALS_PER_SERVER", 10),
			MaxTerminalsGlobal:    envInt("NEXT_PANEL_MAX_TERMINALS_GLOBAL", 200),
			MaxConnPerServer:      envInt("NEXT_PANEL_MAX_CONN_PER_SERVER", 4),
			MaxConnPerUser:        envInt("NEXT_PANEL_MAX_CONN_PER_USER", 8),
			MaxFileListEntries:    envInt("NEXT_PANEL_MAX_FILE_LIST_ENTRIES", 5000),
			MaxPreviewBytes:       envInt64("NEXT_PANEL_MAX_PREVIEW_BYTES", 1<<20), // 1 MiB
			MaxArchiveEntries:     envInt("NEXT_PANEL_MAX_ARCHIVE_ENTRIES", 100_000),
			MaxArchiveTotalBytes:  envInt64("NEXT_PANEL_MAX_ARCHIVE_TOTAL_BYTES", 4<<30),
			MaxArchiveFileBytes:   envInt64("NEXT_PANEL_MAX_ARCHIVE_FILE_BYTES", 1<<30),
			MaxArchiveRatio:       envInt("NEXT_PANEL_MAX_ARCHIVE_RATIO", 100),
			MaxCommandOutputBytes: envInt64("NEXT_PANEL_MAX_COMMAND_OUTPUT_BYTES", 1<<20),
			MetricsPointBudget:    envInt("NEXT_PANEL_METRICS_POINT_BUDGET", 1500),
		},
		Features: Features{
			LocalExecutionEnabled: envBool("NEXT_PANEL_LOCAL_EXECUTION_ENABLED", false),
			LocalFileRoots:        envList("NEXT_PANEL_LOCAL_FILE_ROOTS"),
			ContainersEnabled:     envBool("NEXT_PANEL_CONTAINERS_ENABLED", false),
			ServicesEnabled:       envBool("NEXT_PANEL_SERVICES_ENABLED", false),

			MetricInterval:        envDuration("NEXT_PANEL_METRIC_INTERVAL", 5*time.Second),
			MetricRetentionRaw:    envDuration("NEXT_PANEL_METRIC_RETENTION_RAW", 24*time.Hour),
			MetricRetention5m:     envDuration("NEXT_PANEL_METRIC_RETENTION_5M", 30*24*time.Hour),
			MetricRetention1h:     envDuration("NEXT_PANEL_METRIC_RETENTION_1H", 365*24*time.Hour),
			AuditRetention:        envDuration("NEXT_PANEL_AUDIT_RETENTION", 365*24*time.Hour),
			LoginHistoryRetention: envDuration("NEXT_PANEL_LOGIN_HISTORY_RETENTION", 180*24*time.Hour),
			AppLogRetention:       envDuration("NEXT_PANEL_APP_LOG_RETENTION", 30*24*time.Hour),
			BackupRetention:       envInt("NEXT_PANEL_BACKUP_RETENTION", 7),
			BackupDir:             envString("NEXT_PANEL_BACKUP_DIR", ""),

			SchedulerEnabled: envBool("NEXT_PANEL_SCHEDULER_ENABLED", true),
			WorkersEnabled:   envBool("NEXT_PANEL_WORKERS_ENABLED", true),
			WorkerCount:      envInt("NEXT_PANEL_WORKER_COUNT", 4),
		},
		Timeouts: Timeouts{
			SSHConnect:       envDuration("NEXT_PANEL_SSH_CONNECT_TIMEOUT", 10*time.Second),
			SSHAuth:          envDuration("NEXT_PANEL_SSH_AUTH_TIMEOUT", 15*time.Second),
			Command:          envDuration("NEXT_PANEL_COMMAND_TIMEOUT", 30*time.Second),
			Metrics:          envDuration("NEXT_PANEL_METRICS_TIMEOUT", 0), // 0 => 2x interval
			DatabaseQuery:    envDuration("NEXT_PANEL_DB_QUERY_TIMEOUT", 15*time.Second),
			HTTPRequest:      envDuration("NEXT_PANEL_HTTP_TIMEOUT", 60*time.Second),
			FileIdle:         envDuration("NEXT_PANEL_FILE_IDLE_TIMEOUT", 30*time.Minute),
			TerminalIdle:     envDuration("NEXT_PANEL_TERMINAL_IDLE_TIMEOUT", 30*time.Minute),
			SSHKeepAlive:     envDuration("NEXT_PANEL_SSH_KEEPALIVE", 30*time.Second),
			SSHIdle:          envDuration("NEXT_PANEL_SSH_IDLE_TIMEOUT", 5*time.Minute),
			SSHMaxReconnects: envInt("NEXT_PANEL_SSH_MAX_RECONNECTS", 5),
		},
	}

	cfg.Security.PreviousKeys = parsePreviousKeys(os.Getenv("NEXT_PANEL_ENCRYPTION_PREVIOUS_KEYS"))

	if err := cfg.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parsePreviousKeys reads "id:base64,id:base64" pairs used during key rotation.
func parsePreviousKeys(raw string) map[uint8]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make(map[uint8]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idStr, key, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil || id <= 0 || id > 255 {
			continue
		}
		out[uint8(id)] = strings.TrimSpace(key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (c *Config) normalizeAndValidate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// --- environment -------------------------------------------------------
	switch c.Env {
	case EnvDevelopment, EnvProduction:
	default:
		add("NEXT_PANEL_ENV must be %q or %q, got %q", EnvDevelopment, EnvProduction, c.Env)
	}

	// --- external scheme ---------------------------------------------------
	switch c.App.ExternalScheme {
	case "http", "https":
	default:
		add("NEXT_PANEL_EXTERNAL_SCHEME must be \"http\" or \"https\", got %q", c.App.ExternalScheme)
	}
	if c.App.IsProduction() && c.App.ExternalScheme != "https" {
		add("NEXT_PANEL_EXTERNAL_SCHEME must be \"https\" in production; refusing to run with insecure cookies")
	}

	switch c.App.LogLevel {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		add("NEXT_PANEL_LOG_LEVEL must be DEBUG, INFO, WARN or ERROR, got %q", c.App.LogLevel)
	}
	switch c.App.LogFormat {
	case "json", "text":
	default:
		add("NEXT_PANEL_LOG_FORMAT must be \"json\" or \"text\", got %q", c.App.LogFormat)
	}

	if _, err := time.LoadLocation(c.App.Timezone); err != nil {
		add("NEXT_PANEL_TIMEZONE %q is not a known timezone", c.App.Timezone)
	}

	if _, _, err := net.SplitHostPort(c.App.ListenAddr); err != nil {
		add("NEXT_PANEL_LISTEN %q is not a valid host:port", c.App.ListenAddr)
	}

	if u, err := url.Parse(c.App.BaseURL); err != nil || u.Scheme == "" || u.Host == "" {
		add("NEXT_PANEL_BASE_URL %q is not a valid absolute URL", c.App.BaseURL)
	}

	// --- database ----------------------------------------------------------
	switch c.Database.Driver {
	case DriverPostgres:
		if strings.TrimSpace(c.Database.DSN) == "" {
			add("NEXT_PANEL_DB_DSN is required when NEXT_PANEL_DB_DRIVER=postgres")
		}
	case DriverSQLite:
		if strings.TrimSpace(c.Database.DSN) == "" {
			c.Database.SQLitePath = c.App.DataDir + "/nextpanel.db"
		} else {
			c.Database.SQLitePath = c.Database.DSN
		}
		if c.Database.MaxConns != 1 {
			// SQLite permits a single writer. A larger pool produces
			// SQLITE_BUSY under concurrency rather than more throughput
			// (Design Spec §7.4).
			c.Database.MaxConns = 1
		}
	default:
		add("NEXT_PANEL_DB_DRIVER must be %q or %q, got %q", DriverPostgres, DriverSQLite, c.Database.Driver)
	}
	if c.Database.MaxConns < 1 {
		add("NEXT_PANEL_DB_MAX_CONNS must be at least 1")
	}

	// --- encryption --------------------------------------------------------
	switch {
	case strings.TrimSpace(c.Security.EncryptionKey) == "":
		add("NEXT_PANEL_ENCRYPTION_KEY is required; generate one with `nextpanel crypto generate-key`")
	default:
		raw, err := base64.StdEncoding.DecodeString(c.Security.EncryptionKey)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(c.Security.EncryptionKey)
		}
		if err != nil {
			add("NEXT_PANEL_ENCRYPTION_KEY is not valid base64")
		} else if len(raw) != 32 {
			add("NEXT_PANEL_ENCRYPTION_KEY must decode to exactly 32 bytes, got %d", len(raw))
		}
	}
	if c.Security.EncryptionKeyID == 0 {
		add("NEXT_PANEL_ENCRYPTION_KEY_ID must be between 1 and 255")
	}

	// --- sessions ----------------------------------------------------------
	if c.Security.SessionLifetime <= 0 {
		add("NEXT_PANEL_SESSION_LIFETIME must be positive")
	}
	if c.Security.SessionIdle <= 0 {
		add("NEXT_PANEL_SESSION_IDLE must be positive")
	}
	if c.Security.SessionIdle > c.Security.SessionLifetime {
		add("NEXT_PANEL_SESSION_IDLE (%s) must not exceed NEXT_PANEL_SESSION_LIFETIME (%s)",
			c.Security.SessionIdle, c.Security.SessionLifetime)
	}
	if c.Security.ReauthWindow <= 0 {
		add("NEXT_PANEL_REAUTH_WINDOW must be positive")
	}

	// --- bootstrap admin ---------------------------------------------------
	if c.Security.BootstrapAdminEnabled {
		if strings.TrimSpace(c.Security.BootstrapUsername) == "" {
			add("NEXT_PANEL_BOOTSTRAP_USERNAME must not be empty")
		}
		if len(c.Security.BootstrapPassword) < 6 {
			add("NEXT_PANEL_BOOTSTRAP_PASSWORD must be at least 6 characters")
		}
	}

	// --- limits ------------------------------------------------------------
	for _, l := range []struct {
		name string
		val  int
	}{
		{"NEXT_PANEL_MAX_CONCURRENT_UPLOADS", c.Limits.MaxConcurrentUploads},
		{"NEXT_PANEL_MAX_TERMINALS_PER_USER", c.Limits.MaxTerminalsPerUser},
		{"NEXT_PANEL_MAX_TERMINALS_PER_SERVER", c.Limits.MaxTerminalsPerServer},
		{"NEXT_PANEL_MAX_TERMINALS_GLOBAL", c.Limits.MaxTerminalsGlobal},
		{"NEXT_PANEL_MAX_CONN_PER_SERVER", c.Limits.MaxConnPerServer},
		{"NEXT_PANEL_MAX_CONN_PER_USER", c.Limits.MaxConnPerUser},
		{"NEXT_PANEL_MAX_FILE_LIST_ENTRIES", c.Limits.MaxFileListEntries},
		{"NEXT_PANEL_MAX_ARCHIVE_ENTRIES", c.Limits.MaxArchiveEntries},
		{"NEXT_PANEL_MAX_ARCHIVE_RATIO", c.Limits.MaxArchiveRatio},
		{"NEXT_PANEL_METRICS_POINT_BUDGET", c.Limits.MetricsPointBudget},
		{"NEXT_PANEL_RATE_LIMIT_AUTH", c.Security.RateLimitAuth},
		{"NEXT_PANEL_MAX_LOGIN_FAILURES", c.Security.MaxLoginFailures},
		{"NEXT_PANEL_WORKER_COUNT", c.Features.WorkerCount},
	} {
		if l.val < 1 {
			add("%s must be at least 1", l.name)
		}
	}
	for _, l := range []struct {
		name string
		val  int64
	}{
		{"NEXT_PANEL_MAX_UPLOAD_BYTES", c.Limits.MaxUploadBytes},
		{"NEXT_PANEL_MAX_PREVIEW_BYTES", c.Limits.MaxPreviewBytes},
		{"NEXT_PANEL_MAX_ARCHIVE_TOTAL_BYTES", c.Limits.MaxArchiveTotalBytes},
		{"NEXT_PANEL_MAX_ARCHIVE_FILE_BYTES", c.Limits.MaxArchiveFileBytes},
		{"NEXT_PANEL_MAX_COMMAND_OUTPUT_BYTES", c.Limits.MaxCommandOutputBytes},
	} {
		if l.val < 1 {
			add("%s must be at least 1", l.name)
		}
	}

	// --- metrics -----------------------------------------------------------
	if c.Features.MetricInterval < time.Second {
		add("NEXT_PANEL_METRIC_INTERVAL must be at least 1s (over SSH a shorter interval saturates the connection)")
	}
	if c.Timeouts.Metrics <= 0 {
		c.Timeouts.Metrics = 2 * c.Features.MetricInterval
	}
	if c.Features.MetricRetention5m < c.Features.MetricRetentionRaw {
		add("NEXT_PANEL_METRIC_RETENTION_5M must be greater than or equal to NEXT_PANEL_METRIC_RETENTION_RAW")
	}
	if c.Features.MetricRetention1h < c.Features.MetricRetention5m {
		add("NEXT_PANEL_METRIC_RETENTION_1H must be greater than or equal to NEXT_PANEL_METRIC_RETENTION_5M")
	}

	// --- privileged gates --------------------------------------------------
	if c.Features.LocalExecutionEnabled && len(c.Features.LocalFileRoots) == 0 {
		// Allowed, but the operator must understand local file access is
		// unrestricted. Recorded here so it is a deliberate configuration.
		c.Features.LocalFileRoots = nil
	}

	// --- trusted proxies ---------------------------------------------------
	for _, raw := range envList("NEXT_PANEL_TRUSTED_PROXIES") {
		ipnet, err := parseCIDROrIP(raw)
		if err != nil {
			add("NEXT_PANEL_TRUSTED_PROXIES entry %q is not a valid IP or CIDR", raw)
			continue
		}
		c.Security.TrustedProxies = append(c.Security.TrustedProxies, ipnet)
	}

	// --- allowed origins ---------------------------------------------------
	origins := envList("NEXT_PANEL_ALLOWED_ORIGINS")
	if len(origins) == 0 {
		if u, err := url.Parse(c.App.BaseURL); err == nil && u.Host != "" {
			origins = []string{u.Scheme + "://" + u.Host}
		}
	}
	c.Security.AllowedOrigins = origins

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// ValidationError aggregates every configuration problem so an operator can
// fix them all in one pass rather than one restart at a time.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	b.WriteString("invalid configuration:")
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p)
	}
	return b.String()
}

func parseCIDROrIP(raw string) (*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "/") {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("not an IP")
		}
		if v4 := ip.To4(); v4 != nil {
			return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	_, ipnet, err := net.ParseCIDR(raw)
	return ipnet, err
}

// IsTrustedProxy reports whether the given peer address is a configured
// trusted proxy. Forwarded headers are honoured only for these peers
// (Design Spec §31.5).
func (c *Config) IsTrustedProxy(ip net.IP) bool {
	for _, n := range c.Security.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// --- environment helpers ---------------------------------------------------

func envString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return d
}

func envList(key string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
