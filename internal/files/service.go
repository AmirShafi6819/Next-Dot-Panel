// Package files implements remote file management on top of the provider's
// file primitives. Paths supplied by the browser are normalised, and archive
// extraction is validated entry by entry (Design Spec §17, §19, §92): no path
// traversal, no absolute paths, no links or device nodes, and hard limits on
// entry count and extracted size.
package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// Sentinel errors.
var (
	ErrInvalid  = errors.New("files: invalid path or request")
	ErrTooLarge = errors.New("files: archive exceeds the configured limits")
	ErrUnsafe   = errors.New("files: archive entry is unsafe")
)

// Gateway is the connection gateway (satisfied by *server.Service).
type Gateway interface {
	Connect(ctx context.Context, actor auth.Actor, id domain.ServerID, perm domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error)
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

// Limits bound archive extraction.
type Limits struct {
	MaxEntries    int
	MaxTotalBytes int64
	MaxFileBytes  int64
	MaxRatio      int
}

// Service performs file operations.
type Service struct {
	gw     Gateway
	audit  *audit.Writer
	log    logger
	limits Limits
}

// New builds the files service.
func New(gw Gateway, auditWriter *audit.Writer, log logger, limits Limits) *Service {
	return &Service{gw: gw, audit: auditWriter, log: log, limits: limits}
}

// Meta carries request context onto audit records.
type Meta struct {
	RequestID string
	IP        string
	UserAgent string
}

func cleanRemotePath(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", ErrInvalid
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	return cleaned, nil
}

// List returns the entries of a directory. Requires files.read.
func (s *Service) List(ctx context.Context, actor auth.Actor, id domain.ServerID, dir string) ([]domain.FileInfo, error) {
	dir, err := cleanRemotePath(dir)
	if err != nil {
		return nil, err
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesRead)
	if err != nil {
		return nil, err
	}
	if src != nil {
		defer src.Close()
	}
	return p.ListDir(ctx, dir)
}

// Stat returns one path's metadata. Requires files.read.
func (s *Service) Stat(ctx context.Context, actor auth.Actor, id domain.ServerID, filePath string) (*domain.FileInfo, error) {
	filePath, err := cleanRemotePath(filePath)
	if err != nil {
		return nil, err
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesRead)
	if err != nil {
		return nil, err
	}
	if src != nil {
		defer src.Close()
	}
	return p.Stat(ctx, filePath)
}

// OpenDownload opens a file for streaming download. Requires files.download.
func (s *Service) OpenDownload(ctx context.Context, actor auth.Actor, id domain.ServerID, filePath string, meta Meta) (io.ReadCloser, error) {
	filePath, err := cleanRemotePath(filePath)
	if err != nil {
		return nil, err
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesDownload)
	if err != nil {
		return nil, err
	}
	rc, err := p.OpenRead(ctx, filePath, 0)
	if err != nil {
		if src != nil {
			src.Close()
		}
		return nil, err
	}
	s.record(ctx, actor, id, domain.ActionFileDownloaded, meta, filePath, nil)
	// Closing the stream closes the credential source too.
	return &wrappedReadCloser{ReadCloser: rc, close: src}, nil
}

// Upload streams r into a remote file. Requires files.upload.
func (s *Service) Upload(ctx context.Context, actor auth.Actor, id domain.ServerID, filePath string, mode os.FileMode, size int64, r io.Reader, meta Meta) error {
	filePath, err := cleanRemotePath(filePath)
	if err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o644
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesUpload)
	if err != nil {
		return err
	}
	if src != nil {
		defer src.Close()
	}
	w, err := p.OpenWrite(ctx, filePath, mode, size)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		return fmt.Errorf("files: upload: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("files: upload: %w", err)
	}
	s.record(ctx, actor, id, domain.ActionFileUploaded, meta, filePath, map[string]any{"size": size})
	return nil
}

// Mkdir creates a directory. Requires files.write.
func (s *Service) Mkdir(ctx context.Context, actor auth.Actor, id domain.ServerID, dir string, mode os.FileMode, meta Meta) error {
	dir, err := cleanRemotePath(dir)
	if err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o755
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesWrite)
	if err != nil {
		return err
	}
	if src != nil {
		defer src.Close()
	}
	if err := p.Mkdir(ctx, dir, mode); err != nil {
		return err
	}
	s.record(ctx, actor, id, domain.ActionDirectoryCreated, meta, dir, nil)
	return nil
}

// Rename moves or renames a path. Requires files.write.
func (s *Service) Rename(ctx context.Context, actor auth.Actor, id domain.ServerID, from, to string, meta Meta) error {
	from, err := cleanRemotePath(from)
	if err != nil {
		return err
	}
	to, err = cleanRemotePath(to)
	if err != nil {
		return err
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesWrite)
	if err != nil {
		return err
	}
	if src != nil {
		defer src.Close()
	}
	if err := p.Rename(ctx, from, to); err != nil {
		return err
	}
	s.record(ctx, actor, id, domain.ActionFileRenamed, meta, from, map[string]any{"to": to})
	return nil
}

// Remove deletes paths. Requires files.delete.
func (s *Service) Remove(ctx context.Context, actor auth.Actor, id domain.ServerID, paths []string, recursive bool, meta Meta) error {
	if len(paths) == 0 {
		return ErrInvalid
	}
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		c, err := cleanRemotePath(p)
		if err != nil {
			return err
		}
		if c == "/" {
			return fmt.Errorf("%w: refusing to delete the root directory", ErrInvalid)
		}
		cleaned = append(cleaned, c)
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesDelete)
	if err != nil {
		return err
	}
	if src != nil {
		defer src.Close()
	}
	if err := p.Remove(ctx, cleaned, recursive); err != nil {
		return err
	}
	s.record(ctx, actor, id, domain.ActionFileDeleted, meta, strings.Join(cleaned, ","), map[string]any{"recursive": recursive})
	return nil
}

func (s *Service) record(ctx context.Context, actor auth.Actor, id domain.ServerID, action string, meta Meta, target string, extra map[string]any) {
	if s.audit == nil {
		return
	}
	serverID := id
	md := map[string]any{"path": target}
	for k, v := range extra {
		md[k] = v
	}
	s.audit.Record(ctx, audit.Event{
		ActorID: &actor.UserID, ActorName: actor.Username,
		Action: action, Target: target, ServerID: &serverID,
		Result: domain.ResultSuccess, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		Metadata: md,
	})
}

// wrappedReadCloser closes the credential source when the stream closes.
type wrappedReadCloser struct {
	io.ReadCloser
	close provider.CredentialSource
}

func (w *wrappedReadCloser) Close() error {
	err := w.ReadCloser.Close()
	if w.close != nil {
		w.close.Close()
	}
	return err
}
