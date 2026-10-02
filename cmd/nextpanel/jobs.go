package main

import (
	"context"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/jobs"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
	"github.com/ashaibery/Next-Dot-Panel/internal/terminal"
)

// registerJobHandlers installs the maintenance handlers and starts the pool
// plus a scheduler that enqueues the recurring maintenance jobs.
func registerJobHandlers(ctx context.Context, pool *jobs.Pool, q repos.Queries, term *terminal.Manager, metricRetention, auditRetention, sessionLifetime time.Duration) {
	pool.Register(jobs.KindMetricsRetention, func(ctx context.Context, _ domain.Job, _ jobs.Reporter) error {
		_, err := q.DeleteMetricSamplesBefore(ctx, time.Now().UTC().Add(-metricRetention))
		return err
	})
	pool.Register(jobs.KindSessionCleanup, func(ctx context.Context, _ domain.Job, _ jobs.Reporter) error {
		_, err := q.DeleteExpiredSessions(ctx, time.Now().UTC())
		return err
	})
	pool.Register(jobs.KindAuditPrune, func(ctx context.Context, _ domain.Job, _ jobs.Reporter) error {
		_, err := q.DeleteAuditBefore(ctx, time.Now().UTC().Add(-auditRetention))
		return err
	})
	pool.Register(jobs.KindTerminalSweep, func(context.Context, domain.Job, jobs.Reporter) error {
		term.Sweep(time.Now())
		return nil
	})

	go scheduleMaintenance(ctx, q, sessionLifetime)
}

// scheduleMaintenance enqueues the recurring jobs hourly (and once at start).
// Dedupe keys collapse repeats while one is still queued.
func scheduleMaintenance(ctx context.Context, q repos.Queries, _ time.Duration) {
	enqueue := func() {
		for _, kind := range []string{jobs.KindMetricsRetention, jobs.KindSessionCleanup, jobs.KindAuditPrune, jobs.KindTerminalSweep} {
			key := "maintenance:" + kind
			_, _ = q.EnqueueJob(ctx, repos.EnqueueJobParams{
				Kind: kind, Priority: 10, MaxAttempts: 3,
				RunAt: time.Now().UTC(), DedupeKey: &key,
			})
		}
	}
	enqueue()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			enqueue()
		}
	}
}
