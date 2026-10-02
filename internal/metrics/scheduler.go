package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Scheduler runs one collector per server on a fixed interval. Collection
// failures are logged and retried on the next tick; previous data is never
// erased (Design Spec §267).
type Scheduler struct {
	svc      *Service
	q        repos.Queries
	interval time.Duration
	log      logger

	mu      sync.Mutex
	workers map[domain.ServerID]context.CancelFunc
	stop    context.CancelFunc
}

// NewScheduler builds a scheduler. An interval of zero disables it.
func NewScheduler(svc *Service, q repos.Queries, interval time.Duration, log logger) *Scheduler {
	return &Scheduler{svc: svc, q: q, interval: interval, log: log, workers: map[domain.ServerID]context.CancelFunc{}}
}

// Start begins synchronization and collection. It returns immediately; Stop
// halts it.
func (s *Scheduler) Start(ctx context.Context) {
	if s.interval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.stop = cancel
	s.mu.Unlock()

	go func() {
		s.sync(ctx)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sync(ctx)
			}
		}
	}()
}

// Stop halts all collectors.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	stop := s.stop
	workers := s.workers
	s.workers = map[domain.ServerID]context.CancelFunc{}
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	for _, cancel := range workers {
		cancel()
	}
}

func (s *Scheduler) sync(ctx context.Context) {
	servers, err := s.q.ListAllServers(ctx)
	if err != nil {
		if s.log != nil {
			s.log.Warn(ctx, "metrics scheduler could not list servers", "error", err)
		}
		return
	}
	want := make(map[domain.ServerID]struct{}, len(servers))
	for _, srv := range servers {
		want[srv.ID] = struct{}{}
	}

	s.mu.Lock()
	for id := range want {
		if _, ok := s.workers[id]; !ok {
			wctx, cancel := context.WithCancel(ctx)
			s.workers[id] = cancel
			go s.run(wctx, id)
		}
	}
	for id, cancel := range s.workers {
		if _, ok := want[id]; !ok {
			cancel()
			delete(s.workers, id)
		}
	}
	s.mu.Unlock()
}

func (s *Scheduler) run(ctx context.Context, id domain.ServerID) {
	actor := SystemActor()
	// Collect immediately on start, then on the interval.
	if err := s.svc.CollectAndPersist(ctx, actor, id); err != nil && s.log != nil {
		s.log.Warn(ctx, "metrics collection failed", "server_id", id, "error", err)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.svc.CollectAndPersist(ctx, actor, id); err != nil && s.log != nil {
				s.log.Warn(ctx, "metrics collection failed", "server_id", id, "error", err)
			}
		}
	}
}
