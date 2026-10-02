package dto

import (
	"fmt"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// FileInfo is the public projection of a remote file or directory.
type FileInfo struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Type       string    `json:"type"` // "file" | "dir" | "symlink"
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"` // octal, e.g. "0644"
	Owner      string    `json:"owner,omitempty"`
	Group      string    `json:"group,omitempty"`
	IsDir      bool      `json:"is_dir"`
	IsSymlink  bool      `json:"is_symlink"`
	LinkTarget string    `json:"link_target,omitempty"`
	ModifiedAt time.Time `json:"modified_at"`
}

// FromFileInfo projects a domain file onto the wire format.
func FromFileInfo(f domain.FileInfo) FileInfo {
	kind := "file"
	switch {
	case f.IsSymlink:
		kind = "symlink"
	case f.IsDir:
		kind = "dir"
	}
	return FileInfo{
		Name: f.Name, Path: f.Path, Type: kind, Size: f.Size,
		Mode: fmt.Sprintf("%04o", f.Mode), Owner: f.Owner, Group: f.Group,
		IsDir: f.IsDir, IsSymlink: f.IsSymlink, LinkTarget: f.LinkTarget,
		ModifiedAt: f.ModifiedAt,
	}
}

// FileListResponse is GET /api/v1/servers/{id}/files.
type FileListResponse struct {
	Path    string     `json:"path"`
	Entries []FileInfo `json:"entries"`
}

// MkdirRequest is POST /api/v1/servers/{id}/files/mkdir.
type MkdirRequest struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode,omitempty"`
}

// RenameRequest is POST /api/v1/servers/{id}/files/rename.
type RenameRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// DeleteRequest is POST /api/v1/servers/{id}/files/delete.
type DeleteRequest struct {
	Paths     []string `json:"paths"`
	Recursive bool     `json:"recursive"`
}

// ExtractRequest is POST /api/v1/servers/{id}/files/extract.
type ExtractRequest struct {
	Archive     string `json:"archive"`
	Destination string `json:"destination"`
}
