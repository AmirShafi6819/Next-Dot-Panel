// Package repos is the hand-written adapter layer between the generated sqlc
// packages and the application.
//
// Why this exists (measured, not stylistic): sqlc emits different Go types per
// dialect. For the same query, PostgreSQL produces `Limit int32` and
// `ActorID *int64`, while SQLite produces `Limit int64` and
// `ActorID interface{}`. Generated types therefore cannot be the application's
// types, and services must never see them.
//
// The neutral Queries interface below is what both dialects are adapted onto.
// Repositories are written once against it, so a bug in query-selection logic
// cannot exist in only one dialect.
//
// See docs/research.md 1.4 for the measurements.
package repos

import (
	"context"
	"database/sql"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// Queries is the dialect-neutral query surface used by the repositories.
//
// Numeric parameters are int64 throughout because SQLite produces int64 and
// PostgreSQL int32; the PostgreSQL adapter narrows, which is safe because
// values are validated against domain limits before reaching here.
type Queries interface {
	// --- users -------------------------------------------------------------
	CreateUser(ctx context.Context, p CreateUserParams) (domain.User, error)
	GetUserByID(ctx context.Context, id domain.UserID) (domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	ListUsers(ctx context.Context, p ListUsersParams) ([]domain.User, error)
	CountUsers(ctx context.Context, p CountUsersParams) (int64, error)
	UpdateUser(ctx context.Context, p UpdateUserParams) (domain.User, error)
	SetUserPassword(ctx context.Context, p SetUserPasswordParams) (domain.User, error)
	RecordUserLogin(ctx context.Context, id domain.UserID) error
	SoftDeleteUser(ctx context.Context, id domain.UserID) error

	CountAllUsers(ctx context.Context) (int64, error)
	CountActiveAdmins(ctx context.Context) (int64, error)
	CountUsersWithDefaultCredentials(ctx context.Context) (int64, error)

	// --- roles and permissions ---------------------------------------------
	CreateRole(ctx context.Context, p CreateRoleParams) (domain.Role, error)
	GetRoleByName(ctx context.Context, name string) (domain.Role, error)
	GetRoleByID(ctx context.Context, id domain.RoleID) (domain.Role, error)
	ListRoles(ctx context.Context) ([]domain.Role, error)
	UpdateRole(ctx context.Context, p UpdateRoleParams) (domain.Role, error)
	DeleteRole(ctx context.Context, id domain.RoleID) error

	ListUserRoles(ctx context.Context, userID domain.UserID) ([]domain.Role, error)
	AddUserRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error
	RemoveUserRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error
	ClearUserRoles(ctx context.Context, userID domain.UserID) error

	CreatePermission(ctx context.Context, p CreatePermissionParams) error
	ListPermissions(ctx context.Context) ([]domain.Permission, error)
	ListUserPermissions(ctx context.Context, userID domain.UserID) ([]domain.Permission, error)
	ListRolePermissions(ctx context.Context, roleID domain.RoleID) ([]domain.Permission, error)
	AddRolePermission(ctx context.Context, roleID domain.RoleID, perm domain.Permission) error
	ClearRolePermissions(ctx context.Context, roleID domain.RoleID) error

	// --- sessions ----------------------------------------------------------
	CreateSession(ctx context.Context, p CreateSessionParams) (domain.Session, error)
	GetSessionByTokenHash(ctx context.Context, hash []byte) (domain.Session, error)
	GetSessionByID(ctx context.Context, id string) (domain.Session, error)
	ListUserSessions(ctx context.Context, userID domain.UserID) ([]domain.Session, error)
	ListAllSessions(ctx context.Context, p PageParams) ([]domain.Session, error)
	CountActiveSessions(ctx context.Context) (int64, error)
	TouchSession(ctx context.Context, id string) error
	RevokeSession(ctx context.Context, id string) error
	RevokeUserSessions(ctx context.Context, userID domain.UserID) (int64, error)
	RevokeUserSessionsExcept(ctx context.Context, userID domain.UserID, keep string) (int64, error)
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error)

	// --- login history -----------------------------------------------------
	InsertLoginAttempt(ctx context.Context, p InsertLoginAttemptParams) (domain.LoginAttempt, error)
	ListLoginHistory(ctx context.Context, p LoginHistoryParams) ([]domain.LoginAttempt, error)
	CountLoginHistory(ctx context.Context, p LoginHistoryParams) (int64, error)
	CountRecentLoginFailures(ctx context.Context, username string, since time.Time) (int64, error)
	CountRecentLoginFailuresByIP(ctx context.Context, ip string, since time.Time) (int64, error)

	// --- servers -----------------------------------------------------------
	CreateServer(ctx context.Context, p CreateServerParams) (domain.Server, error)
	GetServerByID(ctx context.Context, id domain.ServerID) (domain.Server, error)
	GetServerByName(ctx context.Context, name string) (domain.Server, error)
	ListServers(ctx context.Context, p ListServersParams) ([]domain.Server, error)
	CountServers(ctx context.Context, p CountServersParams) (int64, error)
	ListAllServers(ctx context.Context) ([]domain.Server, error)
	CountServersByStatus(ctx context.Context) (map[string]int64, error)
	UpdateServer(ctx context.Context, p UpdateServerParams) (domain.Server, error)
	UpdateServerStatus(ctx context.Context, p UpdateServerStatusParams) (domain.Server, error)
	UpdateServerSystemInfo(ctx context.Context, p UpdateServerSystemInfoParams) error
	DeleteServer(ctx context.Context, id domain.ServerID) error
	ServerNameExists(ctx context.Context, name string, exclude domain.ServerID) (bool, error)

	// --- credentials -------------------------------------------------------
	CreateCredential(ctx context.Context, p CreateCredentialParams) (domain.Credential, error)
	GetCredential(ctx context.Context, serverID domain.ServerID) (domain.Credential, error)
	RotateCredential(ctx context.Context, p CreateCredentialParams) (domain.Credential, error)
	DeleteServerCredentials(ctx context.Context, serverID domain.ServerID) error
	ListCredentialCiphertexts(ctx context.Context) ([]CredentialCiphertext, error)
	UpdateCredentialCiphertext(ctx context.Context, id domain.CredentialID, ciphertext []byte) error

	// --- host keys ---------------------------------------------------------
	GetHostKey(ctx context.Context, serverID domain.ServerID) (domain.HostKey, error)
	GetHostKeyByFingerprint(ctx context.Context, serverID domain.ServerID, fingerprint string) (domain.HostKey, error)
	ListHostKeys(ctx context.Context, serverID domain.ServerID) ([]domain.HostKey, error)
	CreateHostKey(ctx context.Context, p CreateHostKeyParams) (domain.HostKey, error)
	UpdateHostKeyState(ctx context.Context, p UpdateHostKeyStateParams) error
	DeleteHostKeys(ctx context.Context, serverID domain.ServerID) error

	// --- tags --------------------------------------------------------------
	UpsertTag(ctx context.Context, name string) (domain.Tag, error)
	ListTags(ctx context.Context) ([]domain.Tag, error)
	AddServerTag(ctx context.Context, serverID domain.ServerID, tagID int64) error
	ClearServerTags(ctx context.Context, serverID domain.ServerID) error
	DeleteOrphanTags(ctx context.Context) (int64, error)

	// --- per-server permissions --------------------------------------------
	ListServerPermissions(ctx context.Context, userID domain.UserID, serverID domain.ServerID) ([]domain.Permission, error)
	GrantServerPermission(ctx context.Context, p GrantServerPermissionParams) error
	ClearServerPermissions(ctx context.Context, userID domain.UserID, serverID domain.ServerID) error
	ListAccessibleServerIDs(ctx context.Context, userID domain.UserID) ([]domain.ServerID, error)
	ListServerPermissionGrants(ctx context.Context, userID domain.UserID) ([]ServerGrant, error)

	// --- audit -------------------------------------------------------------
	InsertAudit(ctx context.Context, p InsertAuditParams) (domain.AuditEvent, error)
	InsertAuditTx(ctx context.Context, tx Tx, p InsertAuditParams) (domain.AuditEvent, error)
	ListAudit(ctx context.Context, p AuditQueryParams) ([]domain.AuditEvent, error)
	CountAudit(ctx context.Context, p AuditQueryParams) (int64, error)
	CountSecurityEvents(ctx context.Context, since time.Time) (int64, error)
	DeleteAuditBefore(ctx context.Context, before time.Time) (int64, error)

	// --- jobs --------------------------------------------------------------
	EnqueueJob(ctx context.Context, p EnqueueJobParams) (domain.Job, error)
	GetJob(ctx context.Context, id int64) (domain.Job, error)
	ListJobs(ctx context.Context, p ListJobsParams) ([]domain.Job, error)
	CountJobs(ctx context.Context, p ListJobsParams) (int64, error)
	CountJobsByStatus(ctx context.Context) (map[string]int64, error)
	ClaimJob(ctx context.Context, workerID string) (domain.Job, error)
	ClaimJobByKind(ctx context.Context, workerID, kind string) (domain.Job, error)
	CompleteJob(ctx context.Context, id int64) error
	UpdateJobProgress(ctx context.Context, id int64, progress float64) error
	HeartbeatJob(ctx context.Context, id int64) error
	FailJob(ctx context.Context, id int64, runAt time.Time, errMsg string) error
	DeadJob(ctx context.Context, id int64, errMsg string) error
	CancelJob(ctx context.Context, id int64) error
	RequeueJob(ctx context.Context, id int64, runAt time.Time) error
	ListStaleJobs(ctx context.Context, olderThan time.Time) ([]domain.Job, error)
	PromoteRetryingJobs(ctx context.Context) (int64, error)
	DeleteFinishedJobsBefore(ctx context.Context, before time.Time) (int64, error)

	// --- metrics -----------------------------------------------------------
	UpsertMetricSample(ctx context.Context, s domain.MetricSample) error
	GetLatestMetricSample(ctx context.Context, serverID domain.ServerID) (domain.MetricSample, error)
	ListMetricSamples(ctx context.Context, p MetricRangeParams) ([]domain.MetricSample, error)
	UpsertMetricFilesystem(ctx context.Context, fs domain.Filesystem) error
	ListLatestFilesystems(ctx context.Context, serverID domain.ServerID) ([]domain.Filesystem, error)
	DeleteMetricSamplesBefore(ctx context.Context, before time.Time) (int64, error)

	// --- misc --------------------------------------------------------------
	Ping(ctx context.Context) error
}

// Tx is a transaction handle accepted by queries that must run inside one.
//
// Audit writes for security-sensitive actions use this so the audit record and
// the change commit or roll back together (Design Spec 27.6): if the audit
// insert fails, the action itself fails rather than going unrecorded.
type Tx = *sql.Tx

// ---------------------------------------------------------------------------
// Parameter and result types
//
// These are plain structs rather than generated Params types so that the
// neutral interface does not leak dialect-specific shapes.
// ---------------------------------------------------------------------------

// PageParams is a limit/offset pair.
type PageParams struct {
	Limit  int64
	Offset int64
}

// CreateUserParams creates a user.
type CreateUserParams struct {
	Username           string
	PasswordHash       string
	DisplayName        string
	IsActive           bool
	IsBootstrapDefault bool
	MustChangePassword bool
}

// ListUsersParams filters a user listing.
type ListUsersParams struct {
	PageParams
	Search   *string
	IsActive *bool
}

// CountUsersParams mirrors ListUsersParams without paging.
type CountUsersParams struct {
	Search   *string
	IsActive *bool
}

// UpdateUserParams edits a user with optimistic locking.
type UpdateUserParams struct {
	ID          domain.UserID
	DisplayName string
	IsActive    bool
	Version     int64
}

// SetUserPasswordParams replaces a password hash.
type SetUserPasswordParams struct {
	ID           domain.UserID
	PasswordHash string
	MustChange   bool
}

// CreateRoleParams creates a role.
type CreateRoleParams struct {
	Name        string
	Description string
	IsSystem    bool
}

// UpdateRoleParams edits a mutable role.
type UpdateRoleParams struct {
	ID          domain.RoleID
	Name        string
	Description string
}

// CreatePermissionParams creates a permission row.
type CreatePermissionParams struct {
	Name        domain.Permission
	Description string
}

// CreateSessionParams creates a session. Only the token hash is stored.
type CreateSessionParams struct {
	ID        string
	UserID    domain.UserID
	TokenHash []byte
	IP        string
	UserAgent string
	ExpiresAt time.Time
}

// InsertLoginAttemptParams records an authentication outcome.
type InsertLoginAttemptParams struct {
	UserID        *domain.UserID
	Username      string
	IP            string
	UserAgent     string
	Success       bool
	FailureReason string
	SessionID     string
}

// LoginHistoryParams filters login history.
type LoginHistoryParams struct {
	PageParams
	UserID  *domain.UserID
	IP      *string
	Success *bool
	From    *time.Time
	To      *time.Time
}

// CreateServerParams creates a server.
type CreateServerParams struct {
	Name          string
	TargetType    domain.TargetType
	Host          string
	Port          int
	Username      string
	AuthMethod    domain.AuthMethod
	HostKeyPolicy domain.HostKeyPolicy
	Tags          []byte // JSON array
	Notes         string
	IsFavourite   bool
}

// ListServersParams filters a server listing.
type ListServersParams struct {
	PageParams
	Search     *string
	Status     *string
	TargetType *string
	Tag        *string
}

// CountServersParams mirrors ListServersParams without paging.
type CountServersParams struct {
	Search     *string
	Status     *string
	TargetType *string
	Tag        *string
}

// UpdateServerParams edits a server with optimistic locking.
type UpdateServerParams struct {
	ID            domain.ServerID
	Name          string
	Host          string
	Port          int
	Username      string
	AuthMethod    domain.AuthMethod
	HostKeyPolicy domain.HostKeyPolicy
	Tags          []byte
	Notes         string
	IsFavourite   bool
	Version       int64
}

// UpdateServerStatusParams updates reachability.
type UpdateServerStatusParams struct {
	ID     domain.ServerID
	Status domain.ServerStatus
	Detail string
}

// UpdateServerSystemInfoParams records discovered system details.
type UpdateServerSystemInfoParams struct {
	ID     domain.ServerID
	OS     string
	Kernel string
	Arch   string
}

// CreateCredentialParams stores credential ciphertext.
type CreateCredentialParams struct {
	ServerID   domain.ServerID
	Kind       domain.AuthMethod
	Ciphertext []byte
	Version    int64
}

// CredentialCiphertext is used by the key-rotation sweep.
type CredentialCiphertext struct {
	ID         domain.CredentialID
	ServerID   domain.ServerID
	Ciphertext []byte
}

// CreateHostKeyParams pins a host key.
type CreateHostKeyParams struct {
	ServerID    domain.ServerID
	Algorithm   string
	Fingerprint string
	PublicKey   []byte
	State       domain.HostKeyState
	TrustedAt   *time.Time
	TrustedBy   *domain.UserID
}

// UpdateHostKeyStateParams changes a host key's trust state.
type UpdateHostKeyStateParams struct {
	ID        int64
	State     domain.HostKeyState
	TrustedAt *time.Time
	TrustedBy *domain.UserID
}

// GrantServerPermissionParams grants one permission on one server to one user.
type GrantServerPermissionParams struct {
	UserID     domain.UserID
	ServerID   domain.ServerID
	Permission domain.Permission
	GrantedBy  *domain.UserID
}

// ServerGrant is a per-server permission grant, used by the UI.
type ServerGrant struct {
	ServerID   domain.ServerID
	Permission domain.Permission
}

// InsertAuditParams writes one audit event.
type InsertAuditParams struct {
	ActorID    *domain.UserID
	ActorName  string
	Action     string
	Target     string
	ServerID   *domain.ServerID
	ServerName string
	Result     domain.AuditResult
	RequestID  string
	IP         string
	UserAgent  string
	Metadata   []byte // JSON object
}

// AuditQueryParams filters the audit trail.
type AuditQueryParams struct {
	PageParams
	ActorID   *domain.UserID
	ServerID  *domain.ServerID
	Action    *string
	Result    *string
	IP        *string
	RequestID *string
	From      *time.Time
	To        *time.Time
	Search    *string
}

// EnqueueJobParams adds a job to the queue.
type EnqueueJobParams struct {
	Kind        string
	Priority    int
	MaxAttempts int
	RunAt       time.Time
	Payload     []byte
	CreatedBy   *domain.UserID
	ServerID    *domain.ServerID
	DedupeKey   *string
}

// ListJobsParams filters a job listing.
type ListJobsParams struct {
	PageParams
	Status    *string
	Kind      *string
	ServerID  *domain.ServerID
	CreatedBy *domain.UserID
}

// MetricRangeParams selects a metric time range.
type MetricRangeParams struct {
	ServerID domain.ServerID
	From     time.Time
	To       time.Time
	Limit    int64
}
