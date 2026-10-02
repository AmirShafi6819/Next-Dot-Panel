// Package jobs runs persistent background work: a pool of workers claims jobs
// from the database, executes registered handlers, and records progress,
// retries and completion. Jobs survive restarts because the queue is the
// database (Design Spec §22).
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Handler executes one job. It receives a context cancelled on shutdown and
// reports progress through Report.
type Handler func(ctx context.Context, job domain.Job, rep Reporter) error

// Reporter publishes progress.
type Reporter interface {
	Report(progress float64)
}

type reporter struct {
	q   repos.Queries
	id  int64
	log logger
}

func (r *reporter) Report(progress float64) {
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	if err := r.q.UpdateJobProgress(context.Background(), r.id, progress); err != nil && r.log != nil {
		r.log.Warn(context.Background(), "job progress update failed", "job_id", r.id, "error", err)
	}
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

// Maintenance job kinds enqueued by the process on a schedule.
const (
	KindMetricsRetention = "metrics-retention"
	KindSessionCleanup   = "session-cleanup"
	KindAuditPrune       = "audit-prune"
	KindTerminalSweep    = "terminal-sweep"
)

// Pool runs workers.
type Pool struct {
	q        repos.Queries
	handlers map[string]Handler
	workers  int
	log      logger

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// New builds a pool. workers of zero means one worker.
func New(q repos.Queries, workers int, log logger) *Pool {
	if workers < 1 {
		workers = 1
	}
	return &Pool{q: q, handlers: map[string]Handler{}, workers: workers, log: log}
}

// Register installs a handler for a job kind. Registering twice replaces it.
func (p *Pool) Register(kind string, h Handler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers[kind] = h
}

// Start launches the workers. Stop halts them.
func (p *Pool) Start(ctx context.Context) {
	p.mu.Lock()
	if p.done != nil {
		p.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	p.mu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.work(ctx, fmt.Sprintf("worker-%d", id))
		}(i)
	}
	go func() {
		wg.Wait()
		close(p.done)
	}()
}

// Stop waits for workers to finish.
func (p *Pool) Stop() {
	p.mu.Lock()
	cancel := p.cancel
	done := p.done
	p.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}

func (p *Pool) work(ctx context.Context, workerID string) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		job, err := p.q.ClaimJob(ctx, workerID)
		if errors.Is(err, sql.ErrNoRows) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		if err != nil {
			if p.log != nil {
				p.log.Warn(ctx, "claiming a job failed", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		backoff = time.Second
		p.run(ctx, workerID, job)
	}
}

func (p *Pool) run(ctx context.Context, workerID string, job domain.Job) {
	p.mu.Lock()
	handler, ok := p.handlers[job.Kind]
	p.mu.Unlock()
	if !ok {
		if err := p.q.DeadJob(ctx, job.ID, fmt.Sprintf("no handler for kind %q", job.Kind)); err != nil && p.log != nil {
			p.log.Error(ctx, "marking a job dead failed", "job_id", job.ID, "error", err)
		}
		_ = workerID
		return
	}

	rep := &reporter{q: p.q, id: job.ID, log: p.log}
	if err := handler(ctx, job, rep); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			_ = p.q.CancelJob(ctx, job.ID)
			return
		}
		if job.Attempts+1 >= job.MaxAttempts {
			if derr := p.q.DeadJob(ctx, job.ID, err.Error()); derr != nil && p.log != nil {
				p.log.Error(ctx, "marking a job dead failed", "job_id", job.ID, "error", derr)
			}
			return
		}
		// Exponential backoff: 1m, 2m, 4m… capped at 30m.
		delay := time.Minute << job.Attempts
		if delay > 30*time.Minute {
			delay = 30 * time.Minute
		}
		if ferr := p.q.FailJob(ctx, job.ID, time.Now().UTC().Add(delay), err.Error()); ferr != nil && p.log != nil {
			p.log.Error(ctx, "recording a job failure failed", "job_id", job.ID, "error", ferr)
		}
		return
	}
	if err := p.q.CompleteJob(ctx, job.ID); err != nil && p.log != nil {
		p.log.Error(ctx, "completing a job failed", "job_id", job.ID, "error", err)
	}
}
