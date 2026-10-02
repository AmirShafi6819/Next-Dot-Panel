package sshprovider

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strconv"

	"github.com/pkg/sftp"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// sftpClient returns the shared SFTP client, creating it on first use.
func (p *Provider) sftpClient() (*sftp.Client, error) {
	p.mu.Lock()
	if p.sftp != nil {
		sc := p.sftp
		p.mu.Unlock()
		return sc, nil
	}
	client := p.client
	p.mu.Unlock()
	if client == nil {
		return nil, provider.NewError(provider.CodeServerOffline, "sftp", errors.New("not connected"))
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		return nil, mapNetworkError("sftp", err)
	}
	p.mu.Lock()
	// Another goroutine may have created one first; keep the earliest.
	if p.sftp == nil {
		p.sftp = sc
	} else {
		_ = sc.Close()
		sc = p.sftp
	}
	p.mu.Unlock()
	return sc, nil
}

// Stat returns metadata for one path (not following symlinks).
func (p *Provider) Stat(_ context.Context, filePath string) (*domain.FileInfo, error) {
	sc, err := p.sftpClient()
	if err != nil {
		return nil, err
	}
	fi, err := sc.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	info := mapFile(filePath, fi)
	if info.IsSymlink {
		if target, lerr := sc.ReadLink(filePath); lerr == nil {
			info.LinkTarget = target
		}
	}
	return &info, nil
}

// ListDir lists one directory.
func (p *Provider) ListDir(_ context.Context, dir string) ([]domain.FileInfo, error) {
	sc, err := p.sftpClient()
	if err != nil {
		return nil, err
	}
	entries, err := sc.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]domain.FileInfo, 0, len(entries))
	for _, fi := range entries {
		out = append(out, mapFile(path.Join(dir, fi.Name()), fi))
	}
	return out, nil
}

// OpenRead opens a file for reading starting at offset.
func (p *Provider) OpenRead(_ context.Context, filePath string, offset int64) (io.ReadCloser, error) {
	sc, err := p.sftpClient()
	if err != nil {
		return nil, err
	}
	f, err := sc.Open(filePath)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	return f, nil
}

// OpenWrite opens a file for writing, truncating it.
func (p *Provider) OpenWrite(_ context.Context, filePath string, mode os.FileMode, _ int64) (io.WriteCloser, error) {
	sc, err := p.sftpClient()
	if err != nil {
		return nil, err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if mode&0o111 != 0 {
		// Preserve an executable bit the caller explicitly asked for.
		_ = sc.Chmod(filePath, mode)
	}
	f, err := sc.OpenFile(filePath, flags)
	if err != nil {
		return nil, err
	}
	_ = sc.Chmod(filePath, mode)
	return f, nil
}

// Remove deletes files, or directories when recursive is set.
func (p *Provider) Remove(_ context.Context, paths []string, recursive bool) error {
	sc, err := p.sftpClient()
	if err != nil {
		return err
	}
	for _, target := range paths {
		if recursive {
			if err := sc.RemoveAll(target); err != nil {
				return err
			}
			continue
		}
		if err := sc.Remove(target); err != nil {
			return err
		}
	}
	return nil
}

// Rename moves a file or directory.
func (p *Provider) Rename(_ context.Context, from, to string) error {
	sc, err := p.sftpClient()
	if err != nil {
		return err
	}
	return sc.Rename(from, to)
}

// Mkdir creates a directory and any missing parents.
func (p *Provider) Mkdir(_ context.Context, dir string, mode os.FileMode) error {
	sc, err := p.sftpClient()
	if err != nil {
		return err
	}
	if err := sc.MkdirAll(dir); err != nil {
		return err
	}
	return sc.Chmod(dir, mode)
}

func mapFile(p string, fi os.FileInfo) domain.FileInfo {
	info := domain.FileInfo{
		Name:       fi.Name(),
		Path:       p,
		Size:       fi.Size(),
		Mode:       uint32(fi.Mode().Perm()),
		IsDir:      fi.IsDir(),
		IsSymlink:  fi.Mode()&os.ModeSymlink != 0,
		ModifiedAt: fi.ModTime(),
	}
	if st, ok := fi.Sys().(*sftp.FileStat); ok {
		// SFTP reports numeric ids; resolving names would need /etc/passwd.
		info.Owner = strconv.FormatUint(uint64(st.UID), 10)
		info.Group = strconv.FormatUint(uint64(st.GID), 10)
	}
	return info
}
