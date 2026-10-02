// Package domain holds Next.Panel's application types.
//
// These are deliberately distinct from the generated store types. sqlc emits
// different Go types per dialect (int32 vs int64 for LIMIT, *int64 vs
// interface{} for optional parameters), so generated types cannot be the
// application's types. Repositories convert between the two; services only
// ever see what is defined here.
//
// See docs/research.md 1.4 for the measurements behind that decision.
package domain

import (
	"time"
)

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// UserID identifies a user.
type UserID int64

// ServerID identifies a managed server.
type ServerID int64

// CredentialID identifies a stored credential.
type CredentialID int64

// RoleID identifies a role.
type RoleID int64

// User is an account that can sign in to Next.Panel.
type User struct {
	ID           UserID
	Username     string
	PasswordHash string // never leaves the auth package or reaches a response
	DisplayName  string
	IsActive     bool

	// IsBootstrapDefault marks the seeded administrator whose password has not
	// been changed. Default-credential detection is this flag, never a
	// comparison against a stored default password.
	IsBootstrapDefault bool
	MustChangePassword bool

	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
	Version     int64

	// Roles and Permissions are populated on demand, not by every query.
	Roles       []Role
	Permissions []Permission
}

// CanSignIn reports whether the account may currently authenticate.
func (u *User) CanSignIn() bool {
	return u != nil && u.IsActive && u.DeletedAt == nil
}

// DisplayNameOrUsername returns the display name, falling back to username.
func (u *User) DisplayNameOrUsername() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

// Role is a named bundle of permissions. Authorization is always checked
// against permissions, never against a role name, so roles stay editable.
type Role struct {
	ID          RoleID
	Name        string
	Description string
	IsSystem    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time

	Permissions []Permission
}

// System role names.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// Permission is a single capability.
type Permission string

// Permission catalogue (Design Spec 12.2).
const (
	PermServersRead    Permission = "servers.read"
	PermServersCreate  Permission = "servers.create"
	PermServersUpdate  Permission = "servers.update"
	PermServersDelete  Permission = "servers.delete"
	PermServersConnect Permission = "servers.connect"
	PermServersHostKey Permission = "servers.hostkey.manage"

	PermTerminalOpen Permission = "terminal.open"

	PermFilesRead     Permission = "files.read"
	PermFilesWrite    Permission = "files.write"
	PermFilesUpload   Permission = "files.upload"
	PermFilesDownload Permission = "files.download"
	PermFilesDelete   Permission = "files.delete"
	PermFilesArchive  Permission = "files.archive"

	PermMetricsRead Permission = "metrics.read"

	PermProcessesRead   Permission = "processes.read"
	PermProcessesSignal Permission = "processes.signal"

	PermServicesRead    Permission = "services.read"
	PermServicesControl Permission = "services.control"

	PermContainersRead    Permission = "containers.read"
	PermContainersControl Permission = "containers.control"
	PermContainersExec    Permission = "containers.exec"

	PermBackupsRead    Permission = "backups.read"
	PermBackupsCreate  Permission = "backups.create"
	PermBackupsRestore Permission = "backups.restore"

	PermUsersRead      Permission = "users.read"
	PermUsersManage    Permission = "users.manage"
	PermAuditRead      Permission = "audit.read"
	PermSettingsManage Permission = "settings.manage"
)

// AllPermissions lists every permission the application knows about. It is the
// source of truth for seeding the permissions table and for validating role
// assignments.
func AllPermissions() []Permission {
	return []Permission{
		PermServersRead, PermServersCreate, PermServersUpdate, PermServersDelete,
		PermServersConnect, PermServersHostKey,
		PermTerminalOpen,
		PermFilesRead, PermFilesWrite, PermFilesUpload, PermFilesDownload,
		PermFilesDelete, PermFilesArchive,
		PermMetricsRead,
		PermProcessesRead, PermProcessesSignal,
		PermServicesRead, PermServicesControl,
		PermContainersRead, PermContainersControl, PermContainersExec,
		PermBackupsRead, PermBackupsCreate, PermBackupsRestore,
		PermUsersRead, PermUsersManage, PermAuditRead, PermSettingsManage,
	}
}

// PermissionDescriptions documents each permission for the UI.
var PermissionDescriptions = map[Permission]string{
	PermServersRead:       "View servers and their status",
	PermServersCreate:     "Add new servers",
	PermServersUpdate:     "Edit server settings and credentials",
	PermServersDelete:     "Remove servers from the panel",
	PermServersConnect:    "Connect to servers",
	PermServersHostKey:    "Trust or replace SSH host keys",
	PermTerminalOpen:      "Open interactive terminals",
	PermFilesRead:         "Browse remote files",
	PermFilesWrite:        "Create, rename and modify remote files",
	PermFilesUpload:       "Upload files to servers",
	PermFilesDownload:     "Download files from servers",
	PermFilesDelete:       "Delete remote files and directories",
	PermFilesArchive:      "Create and extract remote archives",
	PermMetricsRead:       "View resource metrics",
	PermProcessesRead:     "View running processes",
	PermProcessesSignal:   "Send signals to processes",
	PermServicesRead:      "View systemd services",
	PermServicesControl:   "Start, stop and restart services",
	PermContainersRead:    "View containers",
	PermContainersControl: "Start, stop and remove containers",
	PermContainersExec:    "Open a shell inside a container",
	PermBackupsRead:       "View panel backups",
	PermBackupsCreate:     "Create panel backups",
	PermBackupsRestore:    "Restore the panel database",
	PermUsersRead:         "View users",
	PermUsersManage:       "Create, edit and delete users",
	PermAuditRead:         "View the audit trail",
	PermSettingsManage:    "Change global settings",
}

// Has reports whether the given permissions include p.
func Has(granted []Permission, p Permission) bool {
	for _, g := range granted {
		if g == p {
			return true
		}
	}
	return false
}

// HasAny reports whether any of the given permissions is present.
func HasAny(granted []Permission, ps ...Permission) bool {
	for _, p := range ps {
		if Has(granted, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// Session is an authenticated browser session.
type Session struct {
	ID         string
	UserID     UserID
	TokenHash  []byte // SHA-256 of the opaque token; the token is never stored
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time

	// Username is populated by admin-facing list queries.
	Username string
}

// Active reports whether the session may still be used.
func (s *Session) Active(now time.Time) bool {
	return s != nil && s.RevokedAt == nil && s.ExpiresAt.After(now)
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

// TargetType distinguishes how a server is reached.
type TargetType string

const (
	// TargetSSH reaches a remote host over SSH.
	TargetSSH TargetType = "ssh"
	// TargetLocal manages the host Next.Panel runs on. Privileged and disabled
	// by default.
	TargetLocal TargetType = "local"
)

// AuthMethod is how credentials authenticate.
type AuthMethod string

const (
	AuthKey      AuthMethod = "key"
	AuthPassword AuthMethod = "password"
	AuthAgent    AuthMethod = "agent"
)

// HostKeyPolicy controls first-contact behaviour.
type HostKeyPolicy string

const (
	// HostKeyTOFU prompts the operator to trust an unseen key.
	HostKeyTOFU HostKeyPolicy = "TOFU"
	// HostKeyStrict refuses any key that is not already pinned.
	HostKeyStrict HostKeyPolicy = "STRICT"
)

// ServerStatus is the last known reachability of a server.
type ServerStatus string

const (
	StatusUnknown    ServerStatus = "UNKNOWN"
	StatusConnecting ServerStatus = "CONNECTING"
	StatusOnline     ServerStatus = "ONLINE"
	StatusOffline    ServerStatus = "OFFLINE"
	StatusError      ServerStatus = "ERROR"
)

// HostKeyState is the verification state of a stored host key.
type HostKeyState string

const (
	HostKeyUnknown  HostKeyState = "UNKNOWN"
	HostKeyTrusted  HostKeyState = "TRUSTED"
	HostKeyChanged  HostKeyState = "CHANGED"
	HostKeyRejected HostKeyState = "REJECTED"
)

// Target describes where and how to connect. It holds only a credential
// reference; raw credential material never appears here.
type Target struct {
	ID            ServerID
	Type          TargetType
	Host          string
	Port          int
	Username      string
	AuthMethod    AuthMethod
	CredentialRef CredentialID
	HostKeyPolicy HostKeyPolicy
}

// Server is a managed host as shown in the UI.
type Server struct {
	ID     ServerID
	Name   string
	Target Target

	Tags        []string
	Notes       string
	IsFavourite bool

	Status       ServerStatus
	StatusDetail string // bounded and secret-free

	OS     string
	Kernel string
	Arch   string

	LastSeenAt  *time.Time
	LastErrorAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Version     int64 // optimistic locking
}

// IsLocal reports whether this server is the panel's own host.
func (s *Server) IsLocal() bool { return s.Target.Type == TargetLocal }

// Credential is stored authentication material. It exists as a value only
// inside the credentials package; repositories deal in ciphertext.
type Credential struct {
	ID         CredentialID
	ServerID   ServerID
	Kind       AuthMethod
	Ciphertext []byte
	Version    int64
	CreatedAt  time.Time
	RotatedAt  *time.Time
}

// HostKey is a pinned SSH host key.
type HostKey struct {
	ID          int64
	ServerID    ServerID
	Algorithm   string
	Fingerprint string // "SHA256:<base64>"
	PublicKey   []byte
	State       HostKeyState
	FirstSeen   time.Time
	TrustedAt   *time.Time
	TrustedBy   *UserID
}

// Tag is a label that can be applied to servers.
type Tag struct {
	ID          int64
	Name        string
	ServerCount int64
	CreatedAt   time.Time
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// AuditResult is the outcome recorded for an audited action.
type AuditResult string

const (
	ResultSuccess AuditResult = "SUCCESS"
	ResultFailure AuditResult = "FAILURE"
	ResultDenied  AuditResult = "DENIED"
)

// AuditEvent is one entry in the append-only trail.
type AuditEvent struct {
	ID         int64
	Timestamp  time.Time
	ActorID    *UserID
	ActorName  string // denormalised so history survives user deletion
	Action     string
	Target     string
	ServerID   *ServerID
	ServerName string
	Result     AuditResult
	RequestID  string
	IP         string
	UserAgent  string
	Metadata   map[string]any // sanitised; never contains credential material
}

// Audit action vocabulary (Design Spec 27.3).
const (
	ActionLoginSuccess    = "LOGIN_SUCCESS"
	ActionLoginFailed     = "LOGIN_FAILED"
	ActionLogout          = "LOGOUT"
	ActionPasswordChanged = "PASSWORD_CHANGED"
	ActionPasswordReset   = "PASSWORD_RESET"
	ActionReauthSuccess   = "REAUTH_SUCCESS"
	ActionReauthFailed    = "REAUTH_FAILED"
	ActionSessionRevoked  = "SESSION_REVOKED"
	ActionAPITokenCreated = "API_TOKEN_CREATED"
	ActionAPITokenRevoked = "API_TOKEN_REVOKED"
	ActionAPITokenUsed    = "API_TOKEN_USED"

	ActionUserCreated       = "USER_CREATED"
	ActionUserUpdated       = "USER_UPDATED"
	ActionUserDisabled      = "USER_DISABLED"
	ActionUserEnabled       = "USER_ENABLED"
	ActionUserDeleted       = "USER_DELETED"
	ActionRoleChanged       = "ROLE_CHANGED"
	ActionPermissionChanged = "PERMISSION_CHANGED"

	ActionServerCreated          = "SERVER_CREATED"
	ActionServerUpdated          = "SERVER_UPDATED"
	ActionServerDeleted          = "SERVER_DELETED"
	ActionServerConnectionOK     = "SERVER_CONNECTION_SUCCESS"
	ActionServerConnectionFailed = "SERVER_CONNECTION_FAILED"
	ActionHostKeyTrusted         = "SERVER_HOSTKEY_TRUSTED"
	ActionHostKeyChanged         = "SERVER_HOSTKEY_CHANGED"
	ActionHostKeyRejected        = "SERVER_HOSTKEY_REJECTED"
	ActionCredentialRotated      = "SERVER_CREDENTIAL_ROTATED"

	ActionTerminalOpened = "TERMINAL_OPENED"
	ActionTerminalClosed = "TERMINAL_CLOSED"

	ActionFileUploaded        = "FILE_UPLOADED"
	ActionFileDownloaded      = "FILE_DOWNLOADED"
	ActionFileDeleted         = "FILE_DELETED"
	ActionFileRenamed         = "FILE_RENAMED"
	ActionFileMoved           = "FILE_MOVED"
	ActionDirectoryCreated    = "DIRECTORY_CREATED"
	ActionArchiveExtracted    = "ARCHIVE_EXTRACTED"
	ActionArchiveCreated      = "ARCHIVE_CREATED"
	ActionPermissionChangedFS = "PERMISSION_CHANGED"

	ActionProcessTerminated  = "PROCESS_TERMINATED"
	ActionServiceStarted     = "SERVICE_STARTED"
	ActionServiceStopped     = "SERVICE_STOPPED"
	ActionServiceRestarted   = "SERVICE_RESTARTED"
	ActionServiceEnabled     = "SERVICE_ENABLED"
	ActionServiceDisabled    = "SERVICE_DISABLED"
	ActionContainerStarted   = "CONTAINER_STARTED"
	ActionContainerStopped   = "CONTAINER_STOPPED"
	ActionContainerRestarted = "CONTAINER_RESTARTED"
	ActionContainerRemoved   = "CONTAINER_REMOVED"
	ActionContainerExec      = "CONTAINER_EXEC"

	ActionSettingsChanged  = "SETTINGS_CHANGED"
	ActionBackupCreated    = "BACKUP_CREATED"
	ActionBackupRestored   = "BACKUP_RESTORED"
	ActionRetentionApplied = "METRICS_RETENTION_APPLIED"
	ActionAuditPruned      = "AUDIT_PRUNED"

	ActionSecurityEvent = "SECURITY_EVENT"
	ActionAccessDenied  = "ACCESS_DENIED"
)

// ---------------------------------------------------------------------------
// Login history
// ---------------------------------------------------------------------------

// LoginAttempt records one authentication outcome.
type LoginAttempt struct {
	ID            int64
	UserID        *UserID
	Username      string
	IP            string
	UserAgent     string
	Success       bool
	FailureReason string // a category, never the attempted password
	SessionID     string
	Timestamp     time.Time
}

// Failure reason categories.
const (
	FailureUnknownUser     = "unknown_user"
	FailureBadPassword     = "bad_password"
	FailureAccountDisabled = "account_disabled"
	FailureAccountLocked   = "account_locked"
	FailureRateLimited     = "rate_limited"
	FailureSessionExpired  = "session_expired"
	FailureSessionRevoked  = "session_revoked"
)

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

// JobStatus is a job's lifecycle state (Design Spec 22.2).
type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
	JobRetrying  JobStatus = "retrying"
	JobDead      JobStatus = "dead"
	JobCancelled JobStatus = "cancelled"
)

// Terminal reports whether the job has reached a final state.
func (s JobStatus) Terminal() bool {
	switch s {
	case JobSucceeded, JobDead, JobCancelled:
		return true
	default:
		return false
	}
}

// Job is a unit of background work.
type Job struct {
	ID          int64
	Kind        string
	Status      JobStatus
	Priority    int
	Attempts    int
	MaxAttempts int
	RunAt       time.Time
	LockedBy    *string
	LockedAt    *time.Time
	Payload     []byte
	Progress    float64 // 0..1, or -1 when indeterminate
	LastError   string
	CreatedBy   *UserID
	ServerID    *ServerID
	CreatedAt   time.Time
	UpdatedAt   time.Time
	FinishedAt  *time.Time
	DedupeKey   *string
}

// IndeterminateProgress marks a job whose completion cannot be estimated.
const IndeterminateProgress = -1

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

// MetricState distinguishes absent data from a real reading. A missing metric
// is never represented as zero (Design Spec 18.4).
type MetricState string

const (
	StateOK          MetricState = "ok"
	StateStale       MetricState = "stale"
	StateUnavailable MetricState = "unavailable"
	StateUnsupported MetricState = "unsupported"
	StateOffline     MetricState = "offline"
)

// MetricSample is one collection point. Nil fields mean "not collected".
type MetricSample struct {
	ServerID       ServerID
	Timestamp      time.Time
	CPUPct         *float64
	Load1          *float64
	Load5          *float64
	Load15         *float64
	MemTotal       *int64
	MemUsed        *int64
	MemAvailable   *int64
	MemCached      *int64
	MemBuffers     *int64
	SwapTotal      *int64
	SwapUsed       *int64
	NetRxBytes     *int64
	NetTxBytes     *int64
	DiskReadBytes  *int64
	DiskWriteBytes *int64
	UptimeSeconds  *int64
	ProcessCount   *int32
}

// Filesystem is one mounted filesystem's usage.
type Filesystem struct {
	ServerID   ServerID
	Timestamp  time.Time
	MountPoint string
	Device     string
	FSType     string
	TotalBytes *int64
	UsedBytes  *int64
	AvailBytes *int64
	UsedPct    *float64
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

// FileInfo describes a remote file or directory.
type FileInfo struct {
	Name       string
	Path       string
	Size       int64
	Mode       uint32
	IsDir      bool
	IsSymlink  bool
	LinkTarget string
	Owner      string
	Group      string
	ModifiedAt time.Time
	MimeType   string
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

// Process is one entry from /proc.
type Process struct {
	PID       int
	Name      string
	State     string
	Username  string
	CPUPct    *float64 // needs two samples; nil on first read
	MemoryRSS *int64
	StartTime *time.Time
	Command   string
}

// ---------------------------------------------------------------------------
// Services and containers
// ---------------------------------------------------------------------------

// Service is a systemd unit.
type Service struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
	Enabled     bool
}

// ServiceDetail adds the fields shown on a service detail view.
type ServiceDetail struct {
	Service
	MainPID      int
	ExecStart    string
	FragmentPath string
	Since        *time.Time
}

// Container is a Docker or Podman container.
type Container struct {
	ID      string
	Name    string
	Image   string
	State   string
	Status  string
	Created time.Time
	Ports   []string
}

// ---------------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------------

// APIToken is a scoped automation credential. Only its hash is stored.
type APIToken struct {
	ID         int64
	UserID     UserID
	Name       string
	Scopes     []Permission
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	Username   string
}

// Active reports whether the token may still be used.
func (t *APIToken) Active(now time.Time) bool {
	if t == nil || t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt == nil || t.ExpiresAt.After(now)
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

// Default and maximum page sizes.
const (
	DefaultPerPage = 50
	MaxPerPage     = 200
)

// Page describes a paginated request.
type Page struct {
	Number  int
	PerPage int
}

// Normalize clamps the page into a valid range.
func (p Page) Normalize() Page {
	if p.Number < 1 {
		p.Number = 1
	}
	if p.PerPage < 1 {
		p.PerPage = DefaultPerPage
	}
	if p.PerPage > MaxPerPage {
		p.PerPage = MaxPerPage
	}
	return p
}

// Limit returns the SQL LIMIT for this page.
func (p Page) Limit() int { return p.Normalize().PerPage }

// Offset returns the SQL OFFSET for this page.
func (p Page) Offset() int {
	n := p.Normalize()
	return (n.Number - 1) * n.PerPage
}

// PageResult is a page of results plus the total row count.
type PageResult[T any] struct {
	Items   []T
	Total   int64
	Page    int
	PerPage int
}

// NewPageResult builds a result, normalising the echoed page metadata.
func NewPageResult[T any](items []T, total int64, p Page) PageResult[T] {
	n := p.Normalize()
	if items == nil {
		items = []T{}
	}
	return PageResult[T]{Items: items, Total: total, Page: n.Number, PerPage: n.PerPage}
}
