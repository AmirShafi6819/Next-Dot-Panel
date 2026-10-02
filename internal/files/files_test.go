package files

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// ---------------------------------------------------------------------------
// in-memory provider
// ---------------------------------------------------------------------------

type memProvider struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
}

func newMemProvider() *memProvider {
	return &memProvider{files: map[string][]byte{}, dirs: map[string]bool{"/": true}}
}

func (m *memProvider) ID() string { return "mem" }
func (m *memProvider) Connect(context.Context, domain.Target, provider.CredentialSource) error {
	return nil
}
func (m *memProvider) Disconnect(context.Context) error            { return nil }
func (m *memProvider) Status() provider.ConnectionStatus           { return provider.StatusConnected }
func (m *memProvider) Ping(context.Context) (time.Duration, error) { return 0, nil }
func (m *memProvider) Exec(context.Context, provider.Command) (*provider.ExecResult, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "exec", nil)
}
func (m *memProvider) ExecStream(context.Context, provider.Command) (io.ReadCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "exec", nil)
}
func (m *memProvider) OpenPTY(context.Context, provider.PTYOptions) (provider.PTY, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "pty", nil)
}

func (m *memProvider) Stat(_ context.Context, p string) (*domain.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dirs[p] {
		return &domain.FileInfo{Name: path.Base(p), Path: p, IsDir: true, Mode: 0o755}, nil
	}
	if b, ok := m.files[p]; ok {
		return &domain.FileInfo{Name: path.Base(p), Path: p, Size: int64(len(b)), Mode: 0o644}, nil
	}
	return nil, os.ErrNotExist
}

func (m *memProvider) ListDir(_ context.Context, dir string) ([]domain.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dirs[dir] {
		return nil, os.ErrNotExist
	}
	prefix := strings.TrimRight(dir, "/") + "/"
	seen := map[string]bool{}
	var out []domain.FileInfo
	add := func(p string, isDir bool, size int64) {
		rest := strings.TrimPrefix(p, prefix)
		if rest == "" || strings.Contains(rest, "/") {
			return
		}
		if seen[rest] {
			return
		}
		seen[rest] = true
		out = append(out, domain.FileInfo{Name: rest, Path: p, IsDir: isDir, Size: size, Mode: 0o644})
	}
	for p := range m.dirs {
		if strings.HasPrefix(p, prefix) {
			add(p, true, 0)
		}
	}
	for p, b := range m.files {
		if strings.HasPrefix(p, prefix) {
			add(p, false, int64(len(b)))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memProvider) OpenRead(_ context.Context, p string, offset int64) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	if offset > int64(len(b)) {
		offset = int64(len(b))
	}
	return io.NopCloser(bytes.NewReader(b[offset:])), nil
}

type memWriter struct {
	m    *memProvider
	path string
	buf  bytes.Buffer
}

func (w *memWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *memWriter) Close() error {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	w.m.files[w.path] = append([]byte(nil), w.buf.Bytes()...)
	return nil
}

func (m *memProvider) OpenWrite(_ context.Context, p string, _ os.FileMode, _ int64) (io.WriteCloser, error) {
	return &memWriter{m: m, path: p}, nil
}

func (m *memProvider) Remove(_ context.Context, paths []string, recursive bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range paths {
		if recursive {
			prefix := strings.TrimRight(p, "/") + "/"
			for f := range m.files {
				if f == p || strings.HasPrefix(f, prefix) {
					delete(m.files, f)
				}
			}
			for d := range m.dirs {
				if d == p || strings.HasPrefix(d, prefix) {
					delete(m.dirs, d)
				}
			}
			continue
		}
		if _, ok := m.files[p]; !ok {
			if !m.dirs[p] {
				return os.ErrNotExist
			}
		}
		delete(m.files, p)
		delete(m.dirs, p)
	}
	return nil
}

func (m *memProvider) Rename(_ context.Context, from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.files[from]; ok {
		m.files[to] = b
		delete(m.files, from)
		return nil
	}
	if m.dirs[from] {
		m.dirs[to] = true
		delete(m.dirs, from)
		return nil
	}
	return os.ErrNotExist
}

func (m *memProvider) Mkdir(_ context.Context, dir string, _ os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for d := dir; d != "/" && d != "."; d = path.Dir(d) {
		m.dirs[d] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// fake gateway
// ---------------------------------------------------------------------------

type fakeGateway struct {
	p       provider.ServerExecutionProvider
	granted map[domain.Permission]bool
}

func (g *fakeGateway) Connect(_ context.Context, _ auth.Actor, _ domain.ServerID, perm domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error) {
	if g.granted != nil && !g.granted[perm] {
		return nil, nil, errors.New("forbidden")
	}
	return g.p, nil, nil
}

func newService(t *testing.T) (*Service, *memProvider) {
	t.Helper()
	m := newMemProvider()
	return New(&fakeGateway{p: m}, nil, nil, Limits{}), m
}

func actor() auth.Actor {
	return auth.Actor{UserID: 1, Username: "tester", SessionID: "ses", Permissions: domain.AllPermissions()}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestUploadDownloadRoundTrip(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	id := domain.ServerID(1)

	if err := svc.Upload(ctx, actor(), id, "/etc/test.txt", 0o644, 5, strings.NewReader("hello"), Meta{}); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	rc, err := svc.OpenDownload(ctx, actor(), id, "/etc/test.txt", Meta{})
	if err != nil {
		t.Fatalf("OpenDownload: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Fatalf("download = %q, want hello", got)
	}
	fi, err := svc.Stat(ctx, actor(), id, "/etc/test.txt")
	if err != nil || fi.Size != 5 {
		t.Fatalf("Stat = %+v %v", fi, err)
	}
}

func TestListMkdirRenameRemove(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	id := domain.ServerID(1)
	a := actor()

	if err := svc.Mkdir(ctx, a, id, "/data/sub", 0o755, Meta{}); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	_ = svc.Upload(ctx, a, id, "/data/sub/a.txt", 0o644, 1, strings.NewReader("x"), Meta{})
	entries, err := svc.List(ctx, a, id, "/data/sub")
	if err != nil || len(entries) != 1 || entries[0].Name != "a.txt" {
		t.Fatalf("List = %+v %v", entries, err)
	}
	if err := svc.Rename(ctx, a, id, "/data/sub/a.txt", "/data/sub/b.txt", Meta{}); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := svc.Remove(ctx, a, id, []string{"/data/sub/b.txt"}, false, Meta{}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := svc.Stat(ctx, a, id, "/data/sub/b.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat after remove = %v, want not-exist", err)
	}
}

func TestPathValidation(t *testing.T) {
	svc, _ := newService(t)
	ctx := context.Background()
	id := domain.ServerID(1)
	a := actor()

	if err := svc.Remove(ctx, a, id, []string{"/"}, false, Meta{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Remove(/) = %v, want ErrInvalid", err)
	}
	if _, err := svc.List(ctx, a, id, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("List(\"\") = %v, want ErrInvalid", err)
	}
	if _, err := svc.List(ctx, a, id, "/a\x00b"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("List(NUL) = %v, want ErrInvalid", err)
	}
}

func TestSafeJoin(t *testing.T) {
	ok := map[string]string{
		"file.txt":   "/dest/file.txt",
		"a/b/c.txt":  "/dest/a/b/c.txt",
		"a/../b.txt": "/dest/b.txt",
		"./x":        "/dest/x",
	}
	for in, want := range ok {
		got, err := safeJoin("/dest", in)
		if err != nil || got != want {
			t.Errorf("safeJoin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"../evil", "/abs", "a/../../evil", "", "a\\b", ".."} {
		if _, err := safeJoin("/dest", bad); err == nil {
			t.Errorf("safeJoin(%q) succeeded, want rejection", bad)
		}
	}
}

func makeTarGz(t *testing.T, entries map[string]string, extra func(*tar.Writer) error) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		if err := extra(tw); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractTarGzSuccess(t *testing.T) {
	svc, m := newService(t)
	ctx := context.Background()
	id := domain.ServerID(1)
	m.files["/archive.tar.gz"] = makeTarGz(t, map[string]string{"a.txt": "one", "dir/b.txt": "two"}, nil)

	if err := svc.Extract(ctx, actor(), id, "/archive.tar.gz", "/out", Meta{}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if string(m.files["/out/a.txt"]) != "one" || string(m.files["/out/dir/b.txt"]) != "two" {
		t.Fatalf("extracted files = %v", m.files)
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	svc, m := newService(t)
	ctx := context.Background()
	id := domain.ServerID(1)
	m.files["/evil.tar.gz"] = makeTarGz(t, map[string]string{"../evil.txt": "pwn"}, nil)

	if err := svc.Extract(ctx, actor(), id, "/evil.tar.gz", "/out", Meta{}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Extract(traversal) = %v, want ErrUnsafe", err)
	}
}

func TestExtractRejectsSymlink(t *testing.T) {
	svc, m := newService(t)
	ctx := context.Background()
	id := domain.ServerID(1)
	m.files["/link.tar.gz"] = makeTarGz(t, nil, func(tw *tar.Writer) error {
		return tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777})
	})
	if err := svc.Extract(ctx, actor(), id, "/link.tar.gz", "/out", Meta{}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Extract(symlink) = %v, want ErrUnsafe", err)
	}
}

func TestExtractRejectsTooManyEntries(t *testing.T) {
	svc, m := newService(t)
	svc.limits = Limits{MaxEntries: 2}
	ctx := context.Background()
	id := domain.ServerID(1)
	m.files["/many.tar.gz"] = makeTarGz(t, map[string]string{"1": "a", "2": "b", "3": "c"}, nil)
	if err := svc.Extract(ctx, actor(), id, "/many.tar.gz", "/out", Meta{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Extract(many) = %v, want ErrTooLarge", err)
	}
}

func TestExtractUnsupported(t *testing.T) {
	svc, m := newService(t)
	ctx := context.Background()
	id := domain.ServerID(1)
	m.files["/a.rar"] = []byte("nope")
	if err := svc.Extract(ctx, actor(), id, "/a.rar", "/out", Meta{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Extract(rar) = %v, want ErrInvalid", err)
	}
}

func TestPermissionDenied(t *testing.T) {
	m := newMemProvider()
	svc := New(&fakeGateway{p: m, granted: map[domain.Permission]bool{}}, nil, nil, Limits{})
	if _, err := svc.List(context.Background(), actor(), 1, "/"); err == nil {
		t.Fatal("List without permission succeeded")
	}
}
