package provider

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// Factory creates a fresh provider for a target type.
type Factory func() ServerExecutionProvider

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
}

// Registry resolves a target to a provider and keeps connected providers alive
// for reuse, keyed by server id (Design Spec §8.1, §8.4). Callers must
// Invalidate a server when its connection details or credentials change.
type Registry struct {
	mu        sync.Mutex
	factories map[domain.TargetType]Factory
	pool      map[domain.ServerID]*poolEntry
	log       logger
}

type poolEntry struct {
	provider ServerExecutionProvider
	lastUsed time.Time
}

// NewRegistry builds an empty registry.
func NewRegistry(log logger) *Registry {
	return &Registry{
		factories: make(map[domain.TargetType]Factory),
		pool:      make(map[domain.ServerID]*poolEntry),
		log:       log,
	}
}

// Register installs a factory for a target type. Registering twice replaces
// the factory, which is useful in tests.
func (r *Registry) Register(t domain.TargetType, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[t] = f
}

// For returns the provider for a target. A provider for the same server id is
// reused across calls so connections are not re-established per request.
func (r *Registry) For(ctx context.Context, t domain.Target) (ServerExecutionProvider, error) {
	r.mu.Lock()
	factory, ok := r.factories[t.Type]
	r.mu.Unlock()
	if !ok {
		return nil, NewError(CodeUnsupported, "registry.for", fmt.Errorf("no provider for target type %q", t.Type))
	}

	// An unpersisted target (id 0) is never pooled: there is nothing to key on.
	if t.ID == 0 {
		return factory(), nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.pool[t.ID]
	if !ok {
		entry = &poolEntry{provider: factory(), lastUsed: time.Now()}
		r.pool[t.ID] = entry
	}
	entry.lastUsed = time.Now()
	return entry.provider, nil
}

// Release marks a server's provider as idle. The connection is kept for reuse;
// use Invalidate to force it closed.
func (r *Registry) Release(_ context.Context, t domain.Target) error {
	if t.ID == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.pool[t.ID]; ok {
		entry.lastUsed = time.Now()
	}
	return nil
}

// Invalidate closes and forgets a server's pooled provider. It must be called
// when the server is updated, deleted, or has its credentials rotated.
func (r *Registry) Invalidate(ctx context.Context, serverID domain.ServerID) {
	r.mu.Lock()
	entry, ok := r.pool[serverID]
	if ok {
		delete(r.pool, serverID)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	if err := entry.provider.Disconnect(ctx); err != nil && r.log != nil {
		r.log.Warn(ctx, "closing an invalidated provider failed", "server_id", serverID, "error", err)
	}
}

// Reap disconnects providers idle for longer than idleFor. It returns the
// number reaped.
func (r *Registry) Reap(ctx context.Context, idleFor time.Duration) int {
	if idleFor <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-idleFor)
	r.mu.Lock()
	var stale []*poolEntry
	for id, entry := range r.pool {
		if entry.lastUsed.Before(cutoff) {
			stale = append(stale, entry)
			delete(r.pool, id)
		}
	}
	r.mu.Unlock()
	for _, entry := range stale {
		if err := entry.provider.Disconnect(ctx); err != nil && r.log != nil {
			r.log.Warn(ctx, "reaping an idle provider failed", "error", err)
		}
	}
	return len(stale)
}

// Close disconnects every pooled provider. It is called on shutdown.
func (r *Registry) Close(ctx context.Context) {
	r.mu.Lock()
	entries := make([]*poolEntry, 0, len(r.pool))
	for id, entry := range r.pool {
		entries = append(entries, entry)
		delete(r.pool, id)
	}
	r.mu.Unlock()
	for _, entry := range entries {
		if err := entry.provider.Disconnect(ctx); err != nil && r.log != nil {
			r.log.Warn(ctx, "closing a provider during shutdown failed", "error", err)
		}
	}
}
