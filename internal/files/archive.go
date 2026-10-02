package files

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

func (l Limits) withDefaults() Limits {
	if l.MaxEntries <= 0 {
		l.MaxEntries = 10_000
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = 1 << 30 // 1 GiB
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = 256 << 20 // 256 MiB
	}
	return l
}

// Extract unpacks a tar, tar.gz/tgz or zip archive into destDir. Every entry
// is validated before anything is written (Design Spec §19, §92). Requires
// files.archive.
func (s *Service) Extract(ctx context.Context, actor auth.Actor, id domain.ServerID, archivePath, destDir string, meta Meta) error {
	archivePath, err := cleanRemotePath(archivePath)
	if err != nil {
		return err
	}
	destDir, err = cleanRemotePath(destDir)
	if err != nil {
		return err
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermFilesArchive)
	if err != nil {
		return err
	}
	if src != nil {
		defer src.Close()
	}

	lower := strings.ToLower(archivePath)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		err = s.extractZip(ctx, p, archivePath, destDir)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		err = s.extractTar(ctx, p, archivePath, destDir, true)
	case strings.HasSuffix(lower, ".tar"):
		err = s.extractTar(ctx, p, archivePath, destDir, false)
	default:
		return fmt.Errorf("%w: unsupported archive type", ErrInvalid)
	}
	if err != nil {
		return err
	}
	s.record(ctx, actor, id, domain.ActionArchiveExtracted, meta, archivePath, map[string]any{"destination": destDir})
	return nil
}

func (s *Service) extractTar(ctx context.Context, p provider.ServerExecutionProvider, archivePath, destDir string, compressed bool) error {
	rc, err := p.OpenRead(ctx, archivePath, 0)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	var r io.Reader = rc
	if compressed {
		gz, err := gzip.NewReader(rc)
		if err != nil {
			return fmt.Errorf("%w: not a valid gzip stream", ErrInvalid)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}

	limits := s.limits.withDefaults()
	tr := tar.NewReader(r)
	var entries int
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: malformed tar: %v", ErrInvalid, err)
		}
		entries++
		if entries > limits.MaxEntries {
			return ErrTooLarge
		}
		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := p.Mkdir(ctx, target, os.FileMode(hdr.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size > limits.MaxFileBytes {
				return ErrTooLarge
			}
			total += hdr.Size
			if total > limits.MaxTotalBytes {
				return ErrTooLarge
			}
			if err := s.writeEntry(ctx, p, target, os.FileMode(hdr.Mode)&0o777, io.LimitReader(tr, limits.MaxFileBytes)); err != nil {
				return err
			}
		default:
			// Symlinks, hard links, devices and fifos are refused outright.
			return fmt.Errorf("%w: entry %q has unsupported type", ErrUnsafe, hdr.Name)
		}
	}
}

func (s *Service) extractZip(ctx context.Context, p provider.ServerExecutionProvider, archivePath, destDir string) error {
	rc, err := p.OpenRead(ctx, archivePath, 0)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	// archive/zip needs random access; spool to a securely-created temp file.
	tmp, err := os.CreateTemp("", "nextpanel-extract-*.zip")
	if err != nil {
		return fmt.Errorf("files: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	defer func() { _ = tmp.Close() }()

	if _, err := io.Copy(tmp, rc); err != nil {
		return fmt.Errorf("files: spool archive: %w", err)
	}
	fi, err := tmp.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(tmp, fi.Size())
	if err != nil {
		return fmt.Errorf("%w: malformed zip: %v", ErrInvalid, err)
	}

	limits := s.limits.withDefaults()
	if len(zr.File) > limits.MaxEntries {
		return ErrTooLarge
	}
	var total int64
	for _, f := range zr.File {
		target, err := safeJoin(destDir, f.Name)
		if err != nil {
			return err
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 || (!f.FileInfo().IsDir() && !mode.IsRegular()) {
			return fmt.Errorf("%w: entry %q has unsupported type", ErrUnsafe, f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := p.Mkdir(ctx, target, mode.Perm()); err != nil {
				return err
			}
			continue
		}
		if int64(f.UncompressedSize64) > limits.MaxFileBytes {
			return ErrTooLarge
		}
		total += int64(f.UncompressedSize64)
		if total > limits.MaxTotalBytes {
			return ErrTooLarge
		}
		entry, err := f.Open()
		if err != nil {
			return err
		}
		err = s.writeEntry(ctx, p, target, mode.Perm(), io.LimitReader(entry, limits.MaxFileBytes))
		_ = entry.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) writeEntry(ctx context.Context, p provider.ServerExecutionProvider, target string, mode os.FileMode, r io.Reader) error {
	if mode == 0 {
		mode = 0o644
	}
	if parent := path.Dir(target); parent != "." && parent != "/" {
		if err := p.Mkdir(ctx, parent, 0o755); err != nil {
			return err
		}
	}
	w, err := p.OpenWrite(ctx, target, mode, 0)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		return fmt.Errorf("files: write archive entry: %w", err)
	}
	return w.Close()
}

// safeJoin resolves an archive entry name under dest, refusing absolute paths,
// traversal and anything that escapes the destination.
func safeJoin(dest, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) || strings.ContainsRune(name, '\\') {
		return "", ErrUnsafe
	}
	if path.IsAbs(name) {
		return "", fmt.Errorf("%w: absolute path %q", ErrUnsafe, name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: traversal %q", ErrUnsafe, name)
	}
	base := strings.TrimRight(dest, "/")
	if base == "" {
		base = "/"
	}
	target := path.Join(base, clean)
	if base == "/" {
		if !strings.HasPrefix(target, "/") {
			return "", ErrUnsafe
		}
		return target, nil
	}
	if target != base && !strings.HasPrefix(target, base+"/") {
		return "", fmt.Errorf("%w: escapes destination %q", ErrUnsafe, name)
	}
	return target, nil
}
