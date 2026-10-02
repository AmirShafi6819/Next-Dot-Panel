package dto

import (
	"encoding/base64"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// Server is the public projection of a managed server. It never carries
// credential material or credential ids.
type Server struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	TargetType    string     `json:"target_type"`
	Host          string     `json:"host,omitempty"`
	Port          int        `json:"port,omitempty"`
	Username      string     `json:"username,omitempty"`
	AuthMethod    string     `json:"auth_method"`
	HostKeyPolicy string     `json:"host_key_policy"`
	Tags          []string   `json:"tags"`
	Notes         string     `json:"notes,omitempty"`
	IsFavourite   bool       `json:"is_favourite"`
	Status        string     `json:"status"`
	StatusDetail  string     `json:"status_detail,omitempty"`
	OS            string     `json:"os,omitempty"`
	Kernel        string     `json:"kernel,omitempty"`
	Arch          string     `json:"arch,omitempty"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	LastErrorAt   *time.Time `json:"last_error_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	Version       int64      `json:"version"`
}

// FromServer projects a domain server onto the wire format.
func FromServer(s domain.Server) Server {
	return Server{
		ID: int64(s.ID), Name: s.Name,
		TargetType: string(s.Target.Type), Host: s.Target.Host, Port: s.Target.Port, Username: s.Target.Username,
		AuthMethod: string(s.Target.AuthMethod), HostKeyPolicy: string(s.Target.HostKeyPolicy),
		Tags: s.Tags, Notes: s.Notes, IsFavourite: s.IsFavourite,
		Status: string(s.Status), StatusDetail: s.StatusDetail,
		OS: s.OS, Kernel: s.Kernel, Arch: s.Arch,
		LastSeenAt: s.LastSeenAt, LastErrorAt: s.LastErrorAt,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, Version: s.Version,
	}
}

// ServerListResponse is GET /api/v1/servers.
type ServerListResponse struct {
	Servers []Server `json:"servers"`
	Total   int64    `json:"total"`
	Page    int      `json:"page"`
	PerPage int      `json:"per_page"`
}

// ServerRequest is the create/update payload. Credential fields are write-only
// and never echoed.
type ServerRequest struct {
	Name          string   `json:"name"`
	TargetType    string   `json:"target_type"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Username      string   `json:"username"`
	AuthMethod    string   `json:"auth_method"`
	HostKeyPolicy string   `json:"host_key_policy"`
	Tags          []string `json:"tags"`
	Notes         string   `json:"notes"`
	IsFavourite   bool     `json:"is_favourite"`
	Version       int64    `json:"version"`

	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase"`
}

// HostKeyPrompt is returned when a connection is refused because the host key
// is unknown and must be trusted explicitly.
type HostKeyPrompt struct {
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"` // base64
}

// ConnectionTestResponse is POST /api/v1/servers/{id}/test.
type ConnectionTestResponse struct {
	Status    string         `json:"status"`
	LatencyMs int64          `json:"latency_ms,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	HostKey   *HostKeyPrompt `json:"host_key,omitempty"`
}

// TrustHostKeyRequest is POST /api/v1/servers/{id}/hostkeys/trust.
type TrustHostKeyRequest struct {
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"` // base64
}

// HostKey is the public projection of a pinned key.
type HostKey struct {
	ID          int64      `json:"id"`
	Algorithm   string     `json:"algorithm"`
	Fingerprint string     `json:"fingerprint"`
	State       string     `json:"state"`
	FirstSeen   time.Time  `json:"first_seen"`
	TrustedAt   *time.Time `json:"trusted_at,omitempty"`
}

// FromHostKey projects a domain host key onto the wire format.
func FromHostKey(k domain.HostKey) HostKey {
	return HostKey{
		ID: k.ID, Algorithm: k.Algorithm, Fingerprint: k.Fingerprint,
		State: string(k.State), FirstSeen: k.FirstSeen, TrustedAt: k.TrustedAt,
	}
}

// HostKeysResponse is GET /api/v1/servers/{id}/hostkeys.
type HostKeysResponse struct {
	HostKeys []HostKey `json:"host_keys"`
}

// EncodePublicKey base64-encodes a marshaled SSH public key for the wire.
func EncodePublicKey(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
