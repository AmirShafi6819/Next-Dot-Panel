// Command nextpanel runs the Next.Panel control plane: it validates its
// configuration, runs the startup checks, applies migrations, and serves the
// HTTP API (Design Spec §33.5).
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
	"github.com/ashaibery/Next-Dot-Panel/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches the command line and returns the process exit code. It takes
// its writers as arguments so tests can observe the output without touching
// the real process streams.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			return printVersion(stdout)
		case "crypto":
			return cryptoCommand(args[1:], stdout, stderr)
		case "help", "-h", "--help":
			printUsage(stdout)
			return 0
		default:
			_, _ = fmt.Fprintf(stderr, "nextpanel: unknown command %q\n\n", args[0])
			printUsage(stderr)
			return 2
		}
	}
	return serve(ctx, stdout, stderr)
}

// serve performs the startup checks in order and runs the HTTP server until
// ctx is cancelled. Any failed check is fatal and returns a non-zero exit
// code; the failure reason is logged and never contains a secret (Design
// Spec §33.5).
func serve(ctx context.Context, stdout, stderr io.Writer) int {
	cfg, err := config.Load()
	if err != nil {
		// Configuration problems are aggregated and secret-free, so they go
		// straight to the operator.
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	log := logging.New(stdout, cfg.App.LogFormat, cfg.App.LogLevel)

	if err := checkDataDir(cfg.App.DataDir); err != nil {
		log.Error(ctx, "startup check failed", "check", "data_dir", "error", err)
		return 1
	}

	db, err := store.Open(ctx, cfg, log)
	if err != nil {
		log.Error(ctx, "startup check failed", "check", "database", "error", err)
		return 1
	}
	defer func() { _ = db.Close() }()

	if err := store.Migrate(ctx, db, log); err != nil {
		log.Error(ctx, "startup check failed", "check", "migrations", "error", err)
		return 1
	}

	queries, err := repos.NewQueries(db.Driver, db.DB, db.PGXPool())
	if err != nil {
		log.Error(ctx, "startup check failed", "check", "queries", "error", err)
		return 1
	}
	authSvc := auth.New(queries, auth.Options{
		SessionLifetime:   cfg.Security.SessionLifetime,
		SessionIdle:       cfg.Security.SessionIdle,
		ReauthWindow:      cfg.Security.ReauthWindow,
		BootstrapEnabled:  cfg.Security.BootstrapAdminEnabled,
		BootstrapUsername: cfg.Security.BootstrapUsername,
		BootstrapPassword: cfg.Security.BootstrapPassword,
	}, log)
	if err := authSvc.Bootstrap(ctx); err != nil {
		log.Error(ctx, "startup check failed", "check", "auth_bootstrap", "error", err)
		return 1
	}

	// Binding before serving makes an occupied port a startup failure with a
	// clear message instead of a crash loop.
	ln, err := net.Listen("tcp", cfg.App.ListenAddr)
	if err != nil {
		log.Error(ctx, "startup check failed", "check", "listen", "error", err)
		return 1
	}

	handler := httpapi.New(httpapi.Deps{Config: cfg, DB: db, Log: log, Auth: authSvc})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	build := version.Current()
	log.Info(ctx, "next.panel started",
		"version", build.Version,
		"commit", build.Commit,
		"env", cfg.Env,
		"listen", ln.Addr().String(),
		"db_driver", cfg.Database.Driver,
	)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error(ctx, "http server failed", "error", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		log.Info(ctx, "shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error(ctx, "graceful shutdown failed", "error", err)
			_ = srv.Close()
			return 1
		}
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error(ctx, "http server failed", "error", err)
			return 1
		}
		log.Info(ctx, "stopped")
		return 0
	}
}

// checkDataDir creates the data directory and proves it is writable: a
// read-only or missing volume must fail the start, not the first write
// (Design Spec §33.5).
func checkDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	probe := filepath.Join(dir, ".write-probe")
	// #nosec G304 -- probe is a fixed name joined onto NEXT_PANEL_DATA_DIR,
	// which configuration validation has already accepted.
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("data directory is not writable: %w", err)
	}
	if _, err := f.Write([]byte("ok")); err != nil {
		_ = f.Close()
		return fmt.Errorf("data directory is not writable: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("data directory probe: %w", err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("data directory probe: %w", err)
	}
	return nil
}

// cryptoCommand handles `nextpanel crypto …`. generate-key exists because the
// configuration error for a missing encryption key tells the operator to run
// exactly this (Design Spec §33.5).
func cryptoCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		if args[0] == "generate-key" && len(args) == 1 {
			var key [32]byte
			if _, err := rand.Read(key[:]); err != nil {
				_, _ = fmt.Fprintf(stderr, "nextpanel: generate key: %v\n", err)
				return 1
			}
			_, _ = fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(key[:]))
			return 0
		}
	}
	_, _ = fmt.Fprintln(stderr, "usage: nextpanel crypto generate-key")
	return 2
}

func printVersion(stdout io.Writer) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(version.Current()); err != nil {
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Next.Panel — self-hosted server control panel.

usage:
  nextpanel                      run the server (configuration from environment)
  nextpanel crypto generate-key  print a fresh NEXT_PANEL_ENCRYPTION_KEY value
  nextpanel version              print build metadata as JSON
  nextpanel help                 show this message
`)
}
