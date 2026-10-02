package jobs

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

func openDB(t *testing.T) repos.Queries {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dir, "jobs.db"), MaxConns: 1},
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repos.NewSQLiteQueries(lite.New(db.DB))
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestWorkerCompletesJob(t *testing.T) {
	q := openDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ran int32
	pool := New(q, 1, nil)
	pool.Register("test-ok", func(context.Context, domain.Job, Reporter) error {
		atomic.AddInt32(&ran, 1)
		return nil
	})
	pool.Start(ctx)
	defer pool.Stop()

	job, err := q.EnqueueJob(ctx, repos.EnqueueJobParams{Kind: "test-ok", MaxAttempts: 3, RunAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		got, err := q.GetJob(ctx, job.ID)
		return err == nil && got.Status == domain.JobSucceeded
	}, "job success")
	if atomic.LoadInt32(&ran) != 1 {
		t.Fatalf("handler ran %d times", ran)
	}
}

func TestWorkerRetriesThenDies(t *testing.T) {
	q := openDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ran int32
	pool := New(q, 1, nil)
	pool.Register("test-fail", func(context.Context, domain.Job, Reporter) error {
		atomic.AddInt32(&ran, 1)
		return errors.New("boom")
	})
	pool.Start(ctx)
	defer pool.Stop()

	job, err := q.EnqueueJob(ctx, repos.EnqueueJobParams{Kind: "test-fail", MaxAttempts: 1, RunAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		got, err := q.GetJob(ctx, job.ID)
		return err == nil && got.Status == domain.JobDead
	}, "job dead")
}

func TestUnknownKindGoesDead(t *testing.T) {
	q := openDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := New(q, 1, nil)
	pool.Start(ctx)
	defer pool.Stop()

	job, err := q.EnqueueJob(ctx, repos.EnqueueJobParams{Kind: "no-such-kind", MaxAttempts: 3, RunAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	waitFor(t, 10*time.Second, func() bool {
		got, err := q.GetJob(ctx, job.ID)
		return err == nil && got.Status == domain.JobDead
	}, "unknown kind dead")
}
