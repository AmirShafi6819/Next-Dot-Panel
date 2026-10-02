package metrics

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

func TestParseMeminfo(t *testing.T) {
	raw := []byte("MemTotal:        4024548 kB\nMemFree:           1234 kB\nMemAvailable:    3012345 kB\nCached:            500000 kB\nBuffers:             80000 kB\nSwapTotal:        2097148 kB\nSwapFree:         2097148 kB\n")
	v := parseMeminfo(raw)
	if v.total == nil || *v.total != 4024548*1024 {
		t.Fatalf("MemTotal = %v", v.total)
	}
	if v.available == nil || *v.available != 3012345*1024 {
		t.Fatalf("MemAvailable = %v", v.available)
	}
	if v.swapTotal == nil {
		t.Fatal("SwapTotal missing")
	}
}

func TestParseLoadavgUptimeNetDev(t *testing.T) {
	l1, l5, l15 := parseLoadavg([]byte("0.50 0.30 0.20 1/100 1234\n"))
	if l1 == nil || *l1 != 0.5 || l5 == nil || l15 == nil {
		t.Fatalf("load = %v %v %v", l1, l5, l15)
	}
	up := parseUptime([]byte("12345.67 23456.78\n"))
	if up == nil || *up != 12345 {
		t.Fatalf("uptime = %v", up)
	}
	netdev := []byte("Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000  10  0  0  0  0  0  0    2000  20  0  0  0  0  0  0\n    lo: 5000  50  0  0  0  0  0  0    5000  50  0  0  0  0  0  0\n")
	rx, tx := parseNetDev(netdev)
	if rx == nil || *rx != 1000 || tx == nil || *tx != 2000 {
		t.Fatalf("net = %v %v, want 1000 2000 (lo excluded)", rx, tx)
	}
}

func TestCPUDeltas(t *testing.T) {
	a := parseCPUCounters([]byte("cpu  100 0 50 800 10 0 5 0 0 0\n"))
	b := parseCPUCounters([]byte("cpu  150 0 75 900 15 0 8 0 0 0\n"))
	if a == nil || b == nil {
		t.Fatal("stat did not parse")
	}
	// total delta = (150-100)+(75-50)+(900-800)+(15-10)+(8-5) = 50+25+100+5+3 = 183
	// idle delta = 100+5 = 105 ; busy = 78 ; pct = 78/183*100 ≈ 42.6
	pct := cpuFromStat(b, a)
	if pct == nil || *pct < 42 || *pct > 43 {
		t.Fatalf("cpu = %v, want ≈42.6", pct)
	}
	if cpuFromStat(b, nil) != nil {
		t.Fatal("single reading should yield nil")
	}
}

func TestParseDf(t *testing.T) {
	raw := []byte("Filesystem     Type      1B-blocks        Used   Available Use% Mounted on\n/dev/sda1      ext4    10000000000  2000000000  8000000000  20% /\n")
	fs := parseDf(raw)
	if len(fs) != 1 || fs[0].MountPoint != "/" || *fs[0].TotalBytes != 10000000000 {
		t.Fatalf("df = %+v", fs)
	}
	if fs[0].UsedPct == nil || *fs[0].UsedPct != 20 {
		t.Fatalf("used_pct = %v", fs[0].UsedPct)
	}
}

// ---------------------------------------------------------------------------
// CollectNow with a fake provider
// ---------------------------------------------------------------------------

type fakeFiles struct {
	mu    sync.Mutex
	files map[string][]byte
	exec  string
}

func (f *fakeFiles) ID() string { return "fake" }
func (f *fakeFiles) Connect(context.Context, domain.Target, provider.CredentialSource) error {
	return nil
}
func (f *fakeFiles) Disconnect(context.Context) error            { return nil }
func (f *fakeFiles) Status() provider.ConnectionStatus           { return provider.StatusConnected }
func (f *fakeFiles) Ping(context.Context) (time.Duration, error) { return 0, nil }
func (f *fakeFiles) Exec(context.Context, provider.Command) (*provider.ExecResult, error) {
	return &provider.ExecResult{ExitCode: 0, Stdout: []byte(f.exec)}, nil
}
func (f *fakeFiles) ExecStream(context.Context, provider.Command) (io.ReadCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "exec", nil)
}
func (f *fakeFiles) OpenPTY(context.Context, provider.PTYOptions) (provider.PTY, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "pty", nil)
}
func (f *fakeFiles) Stat(context.Context, string) (*domain.FileInfo, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "stat", nil)
}
func (f *fakeFiles) ListDir(context.Context, string) ([]domain.FileInfo, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "list", nil)
}
func (f *fakeFiles) OpenRead(_ context.Context, p string, _ int64) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(strings.NewReader(string(b))), nil
}
func (f *fakeFiles) OpenWrite(context.Context, string, os.FileMode, int64) (io.WriteCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "write", nil)
}
func (f *fakeFiles) Remove(context.Context, []string, bool) error {
	return provider.NewError(provider.CodeUnsupported, "remove", nil)
}
func (f *fakeFiles) Rename(context.Context, string, string) error {
	return provider.NewError(provider.CodeUnsupported, "rename", nil)
}
func (f *fakeFiles) Mkdir(context.Context, string, os.FileMode) error {
	return provider.NewError(provider.CodeUnsupported, "mkdir", nil)
}

type fakeGateway struct {
	p provider.ServerExecutionProvider
}

func (g *fakeGateway) Connect(context.Context, auth.Actor, domain.ServerID, domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error) {
	return g.p, nil, nil
}

type fakeAuthz struct{}

func (fakeAuthz) Require(context.Context, auth.Actor, domain.Permission, *domain.ServerID) error {
	return nil
}

func newCollector(t *testing.T, f *fakeFiles) *Service {
	t.Helper()
	svc := New(nil, &fakeGateway{p: f}, fakeAuthz{}, nil, nil)
	svc.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	return svc
}

func procFiles() map[string][]byte {
	return map[string][]byte{
		"/proc/stat":    []byte("cpu  100 0 50 800 10 0 5 0 0 0\n"),
		"/proc/meminfo": []byte("MemTotal:        4024548 kB\nMemAvailable:    3012345 kB\nCached:            500000 kB\nBuffers:             80000 kB\nSwapTotal:        2097148 kB\nSwapFree:         1048574 kB\n"),
		"/proc/loadavg": []byte("0.50 0.30 0.20 1/100 1234\n"),
		"/proc/uptime":  []byte("12345.67 23456.78\n"),
		"/proc/net/dev": []byte("Inter-|   Receive |  Transmit\n eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"),
	}
}

func TestCollectNow(t *testing.T) {
	f := &fakeFiles{files: procFiles(), exec: "Filesystem Type 1B-blocks Used Available Use% Mounted on\n/dev/sda1 ext4 100 40 60 40% /\n"}
	svc := newCollector(t, f)
	ctx := context.Background()
	a := auth.Actor{UserID: 1, Permissions: []domain.Permission{domain.PermMetricsRead}}

	first, _, err := svc.CollectNow(ctx, a, 1)
	if err != nil {
		t.Fatalf("CollectNow: %v", err)
	}
	if first.CPUPct != nil {
		t.Fatal("first collection should leave CPUPct empty")
	}
	if first.MemTotal == nil || *first.MemTotal != 4024548*1024 {
		t.Fatalf("MemTotal = %v", first.MemTotal)
	}
	if first.SwapUsed == nil || *first.SwapUsed != (2097148-1048574)*1024 {
		t.Fatalf("SwapUsed = %v", first.SwapUsed)
	}

	f.files["/proc/stat"] = []byte("cpu  200 0 100 1600 20 0 10 0 0 0\n")
	second, fs, err := svc.CollectNow(ctx, a, 1)
	if err != nil {
		t.Fatalf("CollectNow: %v", err)
	}
	if second.CPUPct == nil {
		t.Fatal("second collection should compute CPUPct")
	}
	if len(fs) != 1 || fs[0].MountPoint != "/" {
		t.Fatalf("filesystems = %+v", fs)
	}
	_ = repos.MetricRangeParams{}
}
