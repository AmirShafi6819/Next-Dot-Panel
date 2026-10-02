package dto

import (
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// UserDetail is the administrator's projection of an account.
type UserDetail struct {
	ID                 int64      `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	IsActive           bool       `json:"is_active"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	Roles              []Role     `json:"roles"`
}

// FromUserDetail projects a domain user with roles.
func FromUserDetail(u domain.User) UserDetail {
	roles := make([]Role, 0, len(u.Roles))
	for _, r := range u.Roles {
		roles = append(roles, FromRole(r))
	}
	return UserDetail{
		ID: int64(u.ID), Username: u.Username, DisplayName: u.DisplayName,
		IsActive: u.IsActive, MustChangePassword: u.MustChangePassword,
		LastLoginAt: u.LastLoginAt, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, Roles: roles,
	}
}

// UserListResponse is GET /api/v1/users.
type UserListResponse struct {
	Users []UserDetail `json:"users"`
	Total int64        `json:"total"`
}

// CreateUserRequest is POST /api/v1/users.
type CreateUserRequest struct {
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	Password    string  `json:"password"`
	IsActive    bool    `json:"is_active"`
	RoleIDs     []int64 `json:"role_ids"`
}

// UpdateUserRequest is PATCH /api/v1/users/{id}.
type UpdateUserRequest struct {
	DisplayName string `json:"display_name"`
	IsActive    bool   `json:"is_active"`
	Version     int64  `json:"version"`
}

// ResetPasswordRequest is POST /api/v1/users/{id}/reset-password.
type ResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// LoginHistoryEntry is one login attempt.
type LoginHistoryEntry struct {
	ID            int64     `json:"id"`
	UserID        *int64    `json:"user_id,omitempty"`
	Username      string    `json:"username"`
	IP            string    `json:"ip"`
	UserAgent     string    `json:"user_agent"`
	Success       bool      `json:"success"`
	FailureReason string    `json:"failure_reason,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// FromLoginAttempt projects a domain attempt.
func FromLoginAttempt(a domain.LoginAttempt) LoginHistoryEntry {
	var uid *int64
	if a.UserID != nil {
		v := int64(*a.UserID)
		uid = &v
	}
	return LoginHistoryEntry{
		ID: a.ID, UserID: uid, Username: a.Username, IP: a.IP, UserAgent: a.UserAgent,
		Success: a.Success, FailureReason: a.FailureReason, SessionID: a.SessionID, Timestamp: a.Timestamp,
	}
}

// AuditEntry is one audit event.
type AuditEntry struct {
	ID         int64          `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	ActorID    *int64         `json:"actor_id,omitempty"`
	ActorName  string         `json:"actor_name"`
	Action     string         `json:"action"`
	Target     string         `json:"target"`
	ServerID   *int64         `json:"server_id,omitempty"`
	ServerName string         `json:"server_name,omitempty"`
	Result     string         `json:"result"`
	RequestID  string         `json:"request_id,omitempty"`
	IP         string         `json:"ip,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// FromAuditEvent projects a domain event.
func FromAuditEvent(e domain.AuditEvent) AuditEntry {
	var actorID, serverID *int64
	if e.ActorID != nil {
		v := int64(*e.ActorID)
		actorID = &v
	}
	if e.ServerID != nil {
		v := int64(*e.ServerID)
		serverID = &v
	}
	return AuditEntry{
		ID: e.ID, Timestamp: e.Timestamp, ActorID: actorID, ActorName: e.ActorName,
		Action: e.Action, Target: e.Target, ServerID: serverID, ServerName: e.ServerName,
		Result: string(e.Result), RequestID: e.RequestID, IP: e.IP, UserAgent: e.UserAgent, Metadata: e.Metadata,
	}
}

// AuditListResponse is GET /api/v1/audit.
type AuditListResponse struct {
	Events []AuditEntry `json:"events"`
	Total  int64        `json:"total"`
}

// MetricPoint is one collected sample.
type MetricPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	CPUPct       *float64  `json:"cpu_pct,omitempty"`
	Load1        *float64  `json:"load1,omitempty"`
	Load5        *float64  `json:"load5,omitempty"`
	Load15       *float64  `json:"load15,omitempty"`
	MemTotal     *int64    `json:"mem_total,omitempty"`
	MemAvailable *int64    `json:"mem_available,omitempty"`
	MemCached    *int64    `json:"mem_cached,omitempty"`
	MemBuffers   *int64    `json:"mem_buffers,omitempty"`
	SwapTotal    *int64    `json:"swap_total,omitempty"`
	SwapUsed     *int64    `json:"swap_used,omitempty"`
	NetRxBytes   *int64    `json:"net_rx_bytes,omitempty"`
	NetTxBytes   *int64    `json:"net_tx_bytes,omitempty"`
	UptimeSecs   *int64    `json:"uptime_secs,omitempty"`
}

// FromMetricSample projects a domain sample.
func FromMetricSample(s domain.MetricSample) MetricPoint {
	return MetricPoint{
		Timestamp: s.Timestamp, CPUPct: s.CPUPct, Load1: s.Load1, Load5: s.Load5, Load15: s.Load15,
		MemTotal: s.MemTotal, MemAvailable: s.MemAvailable, MemCached: s.MemCached, MemBuffers: s.MemBuffers,
		SwapTotal: s.SwapTotal, SwapUsed: s.SwapUsed, NetRxBytes: s.NetRxBytes, NetTxBytes: s.NetTxBytes,
		UptimeSecs: s.UptimeSeconds,
	}
}

// DiskUsage is one filesystem snapshot.
type DiskUsage struct {
	MountPoint string    `json:"mount_point"`
	Device     string    `json:"device"`
	FSType     string    `json:"fstype"`
	TotalBytes *int64    `json:"total_bytes,omitempty"`
	UsedBytes  *int64    `json:"used_bytes,omitempty"`
	AvailBytes *int64    `json:"avail_bytes,omitempty"`
	UsedPct    *float64  `json:"used_pct,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// FromFilesystem projects a domain filesystem.
func FromFilesystem(f domain.Filesystem) DiskUsage {
	return DiskUsage{
		MountPoint: f.MountPoint, Device: f.Device, FSType: f.FSType,
		TotalBytes: f.TotalBytes, UsedBytes: f.UsedBytes, AvailBytes: f.AvailBytes, UsedPct: f.UsedPct,
		Timestamp: f.Timestamp,
	}
}

// MetricsLatestResponse is GET /api/v1/servers/{id}/metrics/latest.
type MetricsLatestResponse struct {
	Sample      *MetricPoint `json:"sample,omitempty"`
	Filesystems []DiskUsage  `json:"filesystems"`
}

// MetricsRangeResponse is GET /api/v1/servers/{id}/metrics.
type MetricsRangeResponse struct {
	Samples []MetricPoint `json:"samples"`
}

// Process is one remote process.
type Process struct {
	PID      int      `json:"pid"`
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Username string   `json:"username"`
	CPUPct   *float64 `json:"cpu_pct,omitempty"`
	Memory   *int64   `json:"memory_bytes,omitempty"`
	Command  string   `json:"command,omitempty"`
}

// FromProcess projects a domain process.
func FromProcess(p domain.Process) Process {
	return Process{
		PID: p.PID, Name: p.Name, State: p.State, Username: p.Username,
		CPUPct: p.CPUPct, Memory: p.MemoryRSS, Command: p.Command,
	}
}

// ProcessListResponse is GET /api/v1/servers/{id}/processes.
type ProcessListResponse struct {
	Processes []Process `json:"processes"`
}

// SignalRequest is POST /api/v1/servers/{id}/processes/{pid}/signal.
type SignalRequest struct {
	// Force selects SIGKILL; the default is SIGTERM.
	Force bool `json:"force"`
}
