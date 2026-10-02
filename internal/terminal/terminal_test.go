package terminal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

type fakePTY struct {
	in     bytes.Buffer
	closed bool
	mu     sync.Mutex
}

func (f *fakePTY) Read([]byte) (int, error) { return 0, io.EOF }
func (f *fakePTY) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in.Write(p)
}
func (f *fakePTY) Resize(context.Context, uint16, uint16) error { return nil }
func (f *fakePTY) Wait() (int, error)                           { return 0, nil }
func (f *fakePTY) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

type fakeProvider struct{ pty *fakePTY }

func (f *fakeProvider) ID() string { return "fake" }
func (f *fakeProvider) Connect(context.Context, domain.Target, provider.CredentialSource) error {
	return nil
}
func (f *fakeProvider) Disconnect(context.Context) error            { return nil }
func (f *fakeProvider) Status() provider.ConnectionStatus           { return provider.StatusConnected }
func (f *fakeProvider) Ping(context.Context) (time.Duration, error) { return 0, nil }
func (f *fakeProvider) Exec(context.Context, provider.Command) (*provider.ExecResult, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "exec", nil)
}
func (f *fakeProvider) ExecStream(context.Context, provider.Command) (io.ReadCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "exec", nil)
}
func (f *fakeProvider) OpenPTY(context.Context, provider.PTYOptions) (provider.PTY, error) {
	return f.pty, nil
}
func (f *fakeProvider) Stat(context.Context, string) (*domain.FileInfo, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "stat", nil)
}
func (f *fakeProvider) ListDir(context.Context, string) ([]domain.FileInfo, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "list", nil)
}
func (f *fakeProvider) OpenRead(context.Context, string, int64) (io.ReadCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "read", nil)
}
func (f *fakeProvider) OpenWrite(context.Context, string, os.FileMode, int64) (io.WriteCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "write", nil)
}
func (f *fakeProvider) Remove(context.Context, []string, bool) error {
	return provider.NewError(provider.CodeUnsupported, "remove", nil)
}
func (f *fakeProvider) Rename(context.Context, string, string) error {
	return provider.NewError(provider.CodeUnsupported, "rename", nil)
}
func (f *fakeProvider) Mkdir(context.Context, string, os.FileMode) error {
	return provider.NewError(provider.CodeUnsupported, "mkdir", nil)
}

type fakeGateway struct {
	p   provider.ServerExecutionProvider
	err error
}

func (g *fakeGateway) Connect(_ context.Context, _ auth.Actor, _ domain.ServerID, _ domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error) {
	if g.err != nil {
		return nil, nil, g.err
	}
	return g.p, nil, nil
}

func testActor() auth.Actor {
	return auth.Actor{UserID: 1, Username: "tester", SessionID: "ses", Permissions: domain.AllPermissions()}
}

func TestOpenCloseAndLimits(t *testing.T) {
	mgr := New(&fakeGateway{p: &fakeProvider{pty: &fakePTY{}}}, nil, nil, Limits{PerUser: 1, PerServer: 1, Global: 2})
	ctx := context.Background()
	a := testActor()

	s1, err := mgr.Open(ctx, a, 1, OpenOptions{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if mgr.Count() != 1 {
		t.Fatalf("Count = %d, want 1", mgr.Count())
	}
	if _, err := mgr.Open(ctx, a, 1, OpenOptions{}); !errors.Is(err, ErrLimit) {
		t.Fatalf("second Open = %v, want ErrLimit", err)
	}
	mgr.Close(s1.ID, "test")
	if mgr.Count() != 0 {
		t.Fatalf("Count after Close = %d, want 0", mgr.Count())
	}
	// Closing twice is fine.
	mgr.Close(s1.ID, "test")
}

func TestOpenPermissionDenied(t *testing.T) {
	mgr := New(&fakeGateway{err: errors.New("forbidden")}, nil, nil, Limits{})
	if _, err := mgr.Open(context.Background(), testActor(), 1, OpenOptions{}); err == nil {
		t.Fatal("Open without permission succeeded")
	}
}

func TestCloseForServerAndUser(t *testing.T) {
	mgr := New(&fakeGateway{p: &fakeProvider{pty: &fakePTY{}}}, nil, nil, Limits{})
	ctx := context.Background()
	a1 := testActor()
	a2 := auth.Actor{UserID: 2, Username: "other", SessionID: "ses2", Permissions: domain.AllPermissions()}

	if _, err := mgr.Open(ctx, a1, 1, OpenOptions{}); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := mgr.Open(ctx, a2, 2, OpenOptions{}); err != nil {
		t.Fatalf("Open: %v", err)
	}
	mgr.CloseForServer(1, "server updated")
	if mgr.Count() != 1 {
		t.Fatalf("Count after CloseForServer = %d, want 1", mgr.Count())
	}
	mgr.CloseForUser(2, "revoked")
	if mgr.Count() != 0 {
		t.Fatalf("Count after CloseForUser = %d, want 0", mgr.Count())
	}
}

func TestSweepIdle(t *testing.T) {
	mgr := New(&fakeGateway{p: &fakeProvider{pty: &fakePTY{}}}, nil, nil, Limits{IdleTimeout: time.Millisecond})
	ctx := context.Background()
	if _, err := mgr.Open(ctx, testActor(), 1, OpenOptions{}); err != nil {
		t.Fatalf("Open: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if n := mgr.Sweep(time.Now()); n != 1 {
		t.Fatalf("Sweep = %d, want 1", n)
	}
}
