package provider

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

type stubProvider struct {
	id          string
	disconnects int32
}

func (s *stubProvider) ID() string { return s.id }
func (s *stubProvider) Connect(context.Context, domain.Target, CredentialSource) error {
	return nil
}
func (s *stubProvider) Disconnect(context.Context) error {
	atomic.AddInt32(&s.disconnects, 1)
	return nil
}
func (s *stubProvider) Status() ConnectionStatus { return StatusDisconnected }
func (s *stubProvider) Ping(context.Context) (time.Duration, error) {
	return time.Millisecond, nil
}
func (s *stubProvider) Exec(context.Context, Command) (*ExecResult, error) {
	return &ExecResult{}, nil
}
func (s *stubProvider) ExecStream(context.Context, Command) (io.ReadCloser, error) {
	return io.NopCloser(nil), nil
}

func TestRegistryReusesPerServer(t *testing.T) {
	reg := NewRegistry(nil)
	var created int32
	reg.Register(domain.TargetSSH, func() ServerExecutionProvider {
		atomic.AddInt32(&created, 1)
		return &stubProvider{id: "stub"}
	})
	ctx := context.Background()
	t1 := domain.Target{ID: 1, Type: domain.TargetSSH}
	t2 := domain.Target{ID: 2, Type: domain.TargetSSH}

	p1a, err := reg.For(ctx, t1)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	p1b, _ := reg.For(ctx, t1)
	if p1a != p1b {
		t.Fatal("same server did not reuse its provider")
	}
	p2, _ := reg.For(ctx, t2)
	if p2 == p1a {
		t.Fatal("different servers must not share a provider")
	}
	if got := atomic.LoadInt32(&created); got != 2 {
		t.Fatalf("factories called %d times, want 2", got)
	}

	stub := p1a.(*stubProvider)
	reg.Invalidate(ctx, t1.ID)
	if atomic.LoadInt32(&stub.disconnects) != 1 {
		t.Fatal("Invalidate did not disconnect the provider")
	}
	p1c, _ := reg.For(ctx, t1)
	if p1c == p1a {
		t.Fatal("Invalidate did not forget the provider")
	}
}

func TestRegistryUnsupportedTarget(t *testing.T) {
	reg := NewRegistry(nil)
	if _, err := reg.For(context.Background(), domain.Target{ID: 1, Type: domain.TargetLocal}); CodeOf(err) != CodeUnsupported {
		t.Fatalf("For(unsupported) code = %s, want UNSUPPORTED", CodeOf(err))
	}
}

func TestRegistryReap(t *testing.T) {
	reg := NewRegistry(nil)
	reg.Register(domain.TargetSSH, func() ServerExecutionProvider { return &stubProvider{id: "stub"} })
	ctx := context.Background()
	t1 := domain.Target{ID: 1, Type: domain.TargetSSH}
	p, _ := reg.For(ctx, t1)
	stub := p.(*stubProvider)

	if n := reg.Reap(ctx, time.Hour); n != 0 {
		t.Fatalf("Reap(fresh) = %d, want 0", n)
	}
	time.Sleep(2 * time.Millisecond)
	if n := reg.Reap(ctx, time.Millisecond); n != 1 {
		t.Fatalf("Reap(idle) = %d, want 1", n)
	}
	if atomic.LoadInt32(&stub.disconnects) != 1 {
		t.Fatal("reaped provider was not disconnected")
	}
}
