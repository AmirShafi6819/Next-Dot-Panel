package repos

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	pg "github.com/ashaibery/Next-Dot-Panel/internal/store/postgres"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
)

// PostgresQueries adapts the generated PostgreSQL query set onto the neutral
// Queries interface.
//
// The conversions are mechanical but required: sqlc emits int32 for PostgreSQL
// counters and LIMIT/OFFSET where SQLite emits int64, and wraps nullable values
// in pgtype. Narrowing int64 -> int32 is safe because every value reaching this
// layer is already clamped by the domain (page sizes cap at 200; ids come from
// the database).
type PostgresQueries struct {
	q *pg.Queries
}

// NewPostgresQueries wraps a generated PostgreSQL query set.
func NewPostgresQueries(q *pg.Queries) *PostgresQueries {
	return &PostgresQueries{q: q}
}

// NewPostgresTxQueries returns a query set bound to a transaction, so a change
// and its audit record commit or roll back together.
func NewPostgresTxQueries(tx *sql.Tx) *PostgresQueries {
	adapter := store.NewSqlTxAdapter(tx)
	return &PostgresQueries{q: pg.New(adapter)}
}

// --- users -----------------------------------------------------------------

func pgUser(u pg.User) domain.User {
	out := domain.User{
		ID:                 domain.UserID(u.ID),
		Username:           u.Username,
		PasswordHash:       u.PasswordHash,
		DisplayName:        u.DisplayName,
		IsActive:           u.IsActive,
		IsBootstrapDefault: u.IsBootstrapDefault,
		MustChangePassword: u.MustChangePassword,
		LastLoginAt:        u.LastLoginAt,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
		DeletedAt:          u.DeletedAt,
		Version:            u.Version,
	}
	return out
}

func (a *PostgresQueries) CreateUser(ctx context.Context, p CreateUserParams) (domain.User, error) {
	u, err := a.q.CreateUser(ctx, pg.CreateUserParams{
		Username:           p.Username,
		PasswordHash:       p.PasswordHash,
		DisplayName:        p.DisplayName,
		IsActive:           p.IsActive,
		IsBootstrapDefault: p.IsBootstrapDefault,
		MustChangePassword: p.MustChangePassword,
	})
	return pgUser(u), err
}

func (a *PostgresQueries) GetUserByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	u, err := a.q.GetUserByID(ctx, int64(id))
	return pgUser(u), err
}

func (a *PostgresQueries) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	u, err := a.q.GetUserByUsername(ctx, username)
	return pgUser(u), err
}

func (a *PostgresQueries) ListUsers(ctx context.Context, p ListUsersParams) ([]domain.User, error) {
	rows, err := a.q.ListUsers(ctx, pg.ListUsersParams{
		Limit: i32(p.Limit), Offset: i32(p.Offset),
		Search: p.Search, IsActive: p.IsActive,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.User, 0, len(rows))
	for _, u := range rows {
		out = append(out, pgUser(u))
	}
	return out, nil
}

func (a *PostgresQueries) CountUsers(ctx context.Context, p CountUsersParams) (int64, error) {
	return a.q.CountUsers(ctx, pg.CountUsersParams{Search: p.Search, IsActive: p.IsActive})
}

func (a *PostgresQueries) UpdateUser(ctx context.Context, p UpdateUserParams) (domain.User, error) {
	u, err := a.q.UpdateUser(ctx, pg.UpdateUserParams{
		ID: int64(p.ID), DisplayName: p.DisplayName, IsActive: p.IsActive, Version: p.Version,
	})
	return pgUser(u), err
}

func (a *PostgresQueries) SetUserPassword(ctx context.Context, p SetUserPasswordParams) (domain.User, error) {
	u, err := a.q.SetUserPassword(ctx, pg.SetUserPasswordParams{
		ID: int64(p.ID), PasswordHash: p.PasswordHash, MustChangePassword: p.MustChange,
	})
	return pgUser(u), err
}

func (a *PostgresQueries) RecordUserLogin(ctx context.Context, id domain.UserID) error {
	return a.q.RecordUserLogin(ctx, int64(id))
}

func (a *PostgresQueries) UpdateUserPasswordHash(ctx context.Context, id domain.UserID, hash string) error {
	return a.q.UpdateUserPasswordHash(ctx, pg.UpdateUserPasswordHashParams{
		ID: int64(id), PasswordHash: hash,
	})
}

func (a *PostgresQueries) SoftDeleteUser(ctx context.Context, id domain.UserID) error {
	return a.q.SoftDeleteUser(ctx, int64(id))
}

func (a *PostgresQueries) CountAllUsers(ctx context.Context) (int64, error) {
	return a.q.CountAllUsers(ctx)
}

func (a *PostgresQueries) CountActiveAdmins(ctx context.Context) (int64, error) {
	return a.q.CountActiveAdmins(ctx)
}

func (a *PostgresQueries) CountUsersWithDefaultCredentials(ctx context.Context) (int64, error) {
	return a.q.CountUsersWithDefaultCredentials(ctx)
}

// --- roles and permissions --------------------------------------------------

func (a *PostgresQueries) CreateRole(ctx context.Context, p CreateRoleParams) (domain.Role, error) {
	r, err := a.q.CreateRole(ctx, pg.CreateRoleParams{
		Name: p.Name, Description: p.Description, IsSystem: p.IsSystem,
	})
	if err != nil {
		return domain.Role{}, err
	}
	return pgRole(r), nil
}

func pgRole(r pg.Role) domain.Role {
	return domain.Role{
		ID:          domain.RoleID(r.ID),
		Name:        r.Name,
		Description: r.Description,
		IsSystem:    r.IsSystem,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func (a *PostgresQueries) GetRoleByName(ctx context.Context, name string) (domain.Role, error) {
	r, err := a.q.GetRoleByName(ctx, name)
	return pgRole(r), err
}

func (a *PostgresQueries) GetRoleByID(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	r, err := a.q.GetRoleByID(ctx, int64(id))
	return pgRole(r), err
}

func (a *PostgresQueries) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := a.q.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(rows))
	for _, r := range rows {
		out = append(out, pgRole(r))
	}
	return out, nil
}

func (a *PostgresQueries) UpdateRole(ctx context.Context, p UpdateRoleParams) (domain.Role, error) {
	r, err := a.q.UpdateRole(ctx, pg.UpdateRoleParams{ID: int64(p.ID), Name: p.Name, Description: p.Description})
	return pgRole(r), err
}

func (a *PostgresQueries) DeleteRole(ctx context.Context, id domain.RoleID) error {
	return a.q.DeleteRole(ctx, int64(id))
}

func (a *PostgresQueries) ListUserRoles(ctx context.Context, userID domain.UserID) ([]domain.Role, error) {
	rows, err := a.q.ListUserRoles(ctx, int64(userID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(rows))
	for _, r := range rows {
		out = append(out, pgRole(r))
	}
	return out, nil
}

func (a *PostgresQueries) AddUserRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error {
	return a.q.AddUserRole(ctx, pg.AddUserRoleParams{UserID: int64(userID), RoleID: int64(roleID)})
}

func (a *PostgresQueries) RemoveUserRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error {
	return a.q.RemoveUserRole(ctx, pg.RemoveUserRoleParams{UserID: int64(userID), RoleID: int64(roleID)})
}

func (a *PostgresQueries) ClearUserRoles(ctx context.Context, userID domain.UserID) error {
	return a.q.ClearUserRoles(ctx, int64(userID))
}

func (a *PostgresQueries) CreatePermission(ctx context.Context, p CreatePermissionParams) error {
	_, err := a.q.CreatePermission(ctx, pg.CreatePermissionParams{
		Name: string(p.Name), Description: p.Description,
	})
	return err
}

func (a *PostgresQueries) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	rows, err := a.q.ListPermissions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Permission, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Permission(r.Name))
	}
	return out, nil
}

func (a *PostgresQueries) ListUserPermissions(ctx context.Context, userID domain.UserID) ([]domain.Permission, error) {
	names, err := a.q.ListUserPermissions(ctx, int64(userID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Permission, 0, len(names))
	for _, n := range names {
		out = append(out, domain.Permission(n))
	}
	return out, nil
}

func (a *PostgresQueries) ListRolePermissions(ctx context.Context, roleID domain.RoleID) ([]domain.Permission, error) {
	rows, err := a.q.ListRolePermissions(ctx, int64(roleID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Permission, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Permission(r.Name))
	}
	return out, nil
}

func (a *PostgresQueries) AddRolePermission(ctx context.Context, roleID domain.RoleID, perm domain.Permission) error {
	// Permissions are referenced by id, resolved from the name.
	p, err := a.q.GetPermissionByName(ctx, string(perm))
	if err != nil {
		return err
	}
	return a.q.AddRolePermission(ctx, pg.AddRolePermissionParams{RoleID: int64(roleID), PermissionID: p.ID})
}

func (a *PostgresQueries) ClearRolePermissions(ctx context.Context, roleID domain.RoleID) error {
	return a.q.ClearRolePermissions(ctx, int64(roleID))
}

// --- sessions ---------------------------------------------------------------

func pgSession(s pg.Session) domain.Session {
	return domain.Session{
		ID:         s.ID,
		UserID:     domain.UserID(s.UserID),
		TokenHash:  s.TokenHash,
		IP:         s.Ip,
		UserAgent:  s.UserAgent,
		CreatedAt:  s.CreatedAt,
		LastSeenAt: s.LastSeenAt,
		ExpiresAt:  s.ExpiresAt,
		RevokedAt:  s.RevokedAt,
		ReauthAt:   s.ReauthAt,
	}
}

func (a *PostgresQueries) CreateSession(ctx context.Context, p CreateSessionParams) (domain.Session, error) {
	s, err := a.q.CreateSession(ctx, pg.CreateSessionParams{
		ID: p.ID, UserID: int64(p.UserID), TokenHash: p.TokenHash,
		Ip: p.IP, UserAgent: p.UserAgent, ExpiresAt: p.ExpiresAt,
	})
	return pgSession(s), err
}

func (a *PostgresQueries) GetSessionByTokenHash(ctx context.Context, hash []byte) (domain.Session, error) {
	s, err := a.q.GetSessionByTokenHash(ctx, hash)
	return pgSession(s), err
}

func (a *PostgresQueries) GetSessionByID(ctx context.Context, id string) (domain.Session, error) {
	s, err := a.q.GetSessionByID(ctx, id)
	return pgSession(s), err
}

func (a *PostgresQueries) ListUserSessions(ctx context.Context, userID domain.UserID) ([]domain.Session, error) {
	rows, err := a.q.ListUserSessions(ctx, int64(userID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, 0, len(rows))
	for _, s := range rows {
		out = append(out, pgSession(s))
	}
	return out, nil
}

func (a *PostgresQueries) ListAllSessions(ctx context.Context, p PageParams) ([]domain.Session, error) {
	rows, err := a.q.ListAllSessions(ctx, pg.ListAllSessionsParams{Limit: i32(p.Limit), Offset: i32(p.Offset)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, 0, len(rows))
	for _, s := range rows {
		out = append(out, domain.Session{
			ID: s.ID, UserID: domain.UserID(s.UserID), TokenHash: s.TokenHash,
			IP: s.Ip, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt,
			LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt, RevokedAt: s.RevokedAt,
			ReauthAt: s.ReauthAt,
			Username: s.Username,
		})
	}
	return out, nil
}

func (a *PostgresQueries) CountActiveSessions(ctx context.Context) (int64, error) {
	return a.q.CountActiveSessions(ctx)
}

func (a *PostgresQueries) TouchSession(ctx context.Context, id string) error {
	return a.q.TouchSession(ctx, id)
}

func (a *PostgresQueries) SetSessionReauthAt(ctx context.Context, id string) error {
	return a.q.SetSessionReauthAt(ctx, id)
}

func (a *PostgresQueries) RevokeSession(ctx context.Context, id string) error {
	return a.q.RevokeSession(ctx, id)
}

func (a *PostgresQueries) RevokeUserSessions(ctx context.Context, userID domain.UserID) (int64, error) {
	return a.q.RevokeUserSessions(ctx, int64(userID))
}

func (a *PostgresQueries) RevokeUserSessionsExcept(ctx context.Context, userID domain.UserID, keep string) (int64, error) {
	return a.q.RevokeUserSessionsExcept(ctx, pg.RevokeUserSessionsExceptParams{UserID: int64(userID), ID: keep})
}

func (a *PostgresQueries) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteExpiredSessions(ctx, before)
}

// --- login history ----------------------------------------------------------

func pgLoginAttempt(l pg.LoginHistory) domain.LoginAttempt {
	out := domain.LoginAttempt{
		ID:            l.ID,
		Username:      l.Username,
		IP:            l.Ip,
		UserAgent:     l.UserAgent,
		Success:       l.Success,
		FailureReason: l.FailureReason,
		SessionID:     l.SessionID,
		Timestamp:     l.Ts,
	}
	if l.UserID != nil {
		id := domain.UserID(*l.UserID)
		out.UserID = &id
	}
	return out
}

func (a *PostgresQueries) InsertLoginAttempt(ctx context.Context, p InsertLoginAttemptParams) (domain.LoginAttempt, error) {
	l, err := a.q.InsertLoginHistory(ctx, pg.InsertLoginHistoryParams{
		UserID: optID(p.UserID), Username: p.Username, Ip: p.IP, UserAgent: p.UserAgent,
		Success: p.Success, FailureReason: p.FailureReason, SessionID: p.SessionID,
	})
	return pgLoginAttempt(l), err
}

func (a *PostgresQueries) ListLoginHistory(ctx context.Context, p LoginHistoryParams) ([]domain.LoginAttempt, error) {
	rows, err := a.q.ListLoginHistory(ctx, pg.ListLoginHistoryParams{
		Limit: i32(p.Limit), Offset: i32(p.Offset),
		UserID: optIDValue(p.UserID), Ip: p.IP, Success: p.Success, FromTs: p.From, ToTs: p.To,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.LoginAttempt, 0, len(rows))
	for _, l := range rows {
		out = append(out, pgLoginAttempt(l))
	}
	return out, nil
}

func (a *PostgresQueries) CountLoginHistory(ctx context.Context, p LoginHistoryParams) (int64, error) {
	return a.q.CountLoginHistory(ctx, pg.CountLoginHistoryParams{
		UserID: optIDValue(p.UserID), Ip: p.IP, Success: p.Success, FromTs: p.From, ToTs: p.To,
	})
}

func (a *PostgresQueries) CountRecentLoginFailures(ctx context.Context, username string, since time.Time) (int64, error) {
	return a.q.CountRecentLoginFailures(ctx, pg.CountRecentLoginFailuresParams{Username: username, Ts: since})
}

func (a *PostgresQueries) CountRecentLoginFailuresByIP(ctx context.Context, ip string, since time.Time) (int64, error) {
	return a.q.CountRecentLoginFailuresByIP(ctx, pg.CountRecentLoginFailuresByIPParams{Ip: ip, Ts: since})
}

// --- servers ----------------------------------------------------------------

func decodeTags(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var tags []string
	if err := json.Unmarshal(raw, &tags); err != nil || tags == nil {
		// A single malformed row must not make the whole list unusable.
		return []string{}
	}
	return tags
}

func pgServer(s pg.Server) domain.Server {
	return domain.Server{
		ID:   domain.ServerID(s.ID),
		Name: s.Name,
		Target: domain.Target{
			ID:            domain.ServerID(s.ID),
			Type:          domain.TargetType(s.TargetType),
			Host:          s.Host,
			Port:          int(s.Port),
			Username:      s.Username,
			AuthMethod:    domain.AuthMethod(s.AuthMethod),
			HostKeyPolicy: domain.HostKeyPolicy(s.HostKeyPolicy),
		},
		Tags:         decodeTags(s.Tags),
		Notes:        s.Notes,
		IsFavourite:  s.IsFavourite,
		Status:       domain.ServerStatus(s.Status),
		StatusDetail: s.StatusDetail,
		OS:           s.Os,
		Kernel:       s.Kernel,
		Arch:         s.Arch,
		LastSeenAt:   s.LastSeenAt,
		LastErrorAt:  s.LastErrorAt,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
		Version:      s.Version,
	}
}

func (a *PostgresQueries) CreateServer(ctx context.Context, p CreateServerParams) (domain.Server, error) {
	s, err := a.q.CreateServer(ctx, pg.CreateServerParams{
		Name: p.Name, TargetType: string(p.TargetType), Host: p.Host, Port: i32(int64(p.Port)),
		Username: p.Username, AuthMethod: string(p.AuthMethod), HostKeyPolicy: string(p.HostKeyPolicy),
		Tags: jsonOr(p.Tags, "[]"), Notes: p.Notes, IsFavourite: p.IsFavourite,
	})
	return pgServer(s), err
}

func (a *PostgresQueries) GetServerByID(ctx context.Context, id domain.ServerID) (domain.Server, error) {
	s, err := a.q.GetServerByID(ctx, int64(id))
	return pgServer(s), err
}

func (a *PostgresQueries) GetServerByName(ctx context.Context, name string) (domain.Server, error) {
	s, err := a.q.GetServerByName(ctx, name)
	return pgServer(s), err
}

func (a *PostgresQueries) ListServers(ctx context.Context, p ListServersParams) ([]domain.Server, error) {
	rows, err := a.q.ListServers(ctx, pg.ListServersParams{
		Limit: i32(p.Limit), Offset: i32(p.Offset),
		Search: nullString(p.Search), Status: nullString(p.Status), TargetType: nullString(p.TargetType), Tag: nullString(p.Tag),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Server, 0, len(rows))
	for _, s := range rows {
		out = append(out, pgServer(s))
	}
	return out, nil
}

func (a *PostgresQueries) CountServers(ctx context.Context, p CountServersParams) (int64, error) {
	return a.q.CountServers(ctx, pg.CountServersParams{
		Search: nullString(p.Search), Status: nullString(p.Status), TargetType: nullString(p.TargetType), Tag: nullString(p.Tag),
	})
}

func (a *PostgresQueries) ListAllServers(ctx context.Context) ([]domain.Server, error) {
	rows, err := a.q.ListAllServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Server, 0, len(rows))
	for _, s := range rows {
		out = append(out, pgServer(s))
	}
	return out, nil
}

func (a *PostgresQueries) CountServersByStatus(ctx context.Context) (map[string]int64, error) {
	rows, err := a.q.CountServersByStatus(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Status] = r.Count
	}
	return out, nil
}

func (a *PostgresQueries) UpdateServer(ctx context.Context, p UpdateServerParams) (domain.Server, error) {
	s, err := a.q.UpdateServer(ctx, pg.UpdateServerParams{
		ID: int64(p.ID), Name: p.Name, Host: p.Host, Port: i32(int64(p.Port)),
		Username: p.Username, AuthMethod: string(p.AuthMethod), HostKeyPolicy: string(p.HostKeyPolicy),
		Tags: jsonOr(p.Tags, "[]"), Notes: p.Notes, IsFavourite: p.IsFavourite, Version: p.Version,
	})
	return pgServer(s), err
}

func (a *PostgresQueries) UpdateServerStatus(ctx context.Context, p UpdateServerStatusParams) (domain.Server, error) {
	s, err := a.q.UpdateServerStatus(ctx, pg.UpdateServerStatusParams{
		ID: int64(p.ID), Status: string(p.Status), StatusDetail: p.Detail,
	})
	return pgServer(s), err
}

func (a *PostgresQueries) UpdateServerSystemInfo(ctx context.Context, p UpdateServerSystemInfoParams) error {
	return a.q.UpdateServerSystemInfo(ctx, pg.UpdateServerSystemInfoParams{
		ID: int64(p.ID), Os: p.OS, Kernel: p.Kernel, Arch: p.Arch,
	})
}

func (a *PostgresQueries) DeleteServer(ctx context.Context, id domain.ServerID) error {
	return a.q.DeleteServer(ctx, int64(id))
}

func (a *PostgresQueries) ServerNameExists(ctx context.Context, name string, exclude domain.ServerID) (bool, error) {
	return a.q.ServerNameExists(ctx, pg.ServerNameExistsParams{Name: name, ID: int64(exclude)})
}

// --- credentials ------------------------------------------------------------

func pgCredential(c pg.ServerCredential) domain.Credential {
	return domain.Credential{
		ID:         domain.CredentialID(c.ID),
		ServerID:   domain.ServerID(c.ServerID),
		Kind:       domain.AuthMethod(c.Kind),
		Ciphertext: c.Ciphertext,
		Version:    c.Version,
		CreatedAt:  c.CreatedAt,
		RotatedAt:  c.RotatedAt,
	}
}

func (a *PostgresQueries) CreateCredential(ctx context.Context, p CreateCredentialParams) (domain.Credential, error) {
	c, err := a.q.CreateServerCredential(ctx, pg.CreateServerCredentialParams{
		ServerID: int64(p.ServerID), Kind: string(p.Kind), Ciphertext: p.Ciphertext, Version: p.Version,
	})
	return pgCredential(c), err
}

func (a *PostgresQueries) GetCredential(ctx context.Context, serverID domain.ServerID) (domain.Credential, error) {
	c, err := a.q.GetServerCredential(ctx, int64(serverID))
	return pgCredential(c), err
}

func (a *PostgresQueries) RotateCredential(ctx context.Context, p CreateCredentialParams) (domain.Credential, error) {
	c, err := a.q.RotateServerCredential(ctx, pg.RotateServerCredentialParams{
		ServerID: int64(p.ServerID), Kind: string(p.Kind), Ciphertext: p.Ciphertext,
	})
	return pgCredential(c), err
}

func (a *PostgresQueries) DeleteServerCredentials(ctx context.Context, serverID domain.ServerID) error {
	return a.q.DeleteServerCredentials(ctx, int64(serverID))
}

func (a *PostgresQueries) ListCredentialCiphertexts(ctx context.Context) ([]CredentialCiphertext, error) {
	rows, err := a.q.ListCredentialCiphertexts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]CredentialCiphertext, 0, len(rows))
	for _, r := range rows {
		out = append(out, CredentialCiphertext{
			ID:         domain.CredentialID(r.ID),
			ServerID:   domain.ServerID(r.ServerID),
			Ciphertext: r.Ciphertext,
		})
	}
	return out, nil
}

func (a *PostgresQueries) UpdateCredentialCiphertext(ctx context.Context, id domain.CredentialID, ciphertext []byte) error {
	return a.q.UpdateCredentialCiphertext(ctx, pg.UpdateCredentialCiphertextParams{
		ID: int64(id), Ciphertext: ciphertext,
	})
}

// --- host keys --------------------------------------------------------------

func pgHostKey(h pg.ServerHostKey) domain.HostKey {
	out := domain.HostKey{
		ID:          h.ID,
		ServerID:    domain.ServerID(h.ServerID),
		Algorithm:   h.Algorithm,
		Fingerprint: h.Fingerprint,
		PublicKey:   h.PublicKey,
		State:       domain.HostKeyState(h.State),
		FirstSeen:   h.FirstSeen,
		TrustedAt:   h.TrustedAt,
	}
	if h.TrustedBy != nil {
		id := domain.UserID(*h.TrustedBy)
		out.TrustedBy = &id
	}
	return out
}

func (a *PostgresQueries) GetHostKey(ctx context.Context, serverID domain.ServerID) (domain.HostKey, error) {
	h, err := a.q.GetServerHostKey(ctx, int64(serverID))
	return pgHostKey(h), err
}

func (a *PostgresQueries) GetHostKeyByFingerprint(ctx context.Context, serverID domain.ServerID, fingerprint string) (domain.HostKey, error) {
	h, err := a.q.GetServerHostKeyByFingerprint(ctx, pg.GetServerHostKeyByFingerprintParams{
		ServerID: int64(serverID), Fingerprint: fingerprint,
	})
	return pgHostKey(h), err
}

func (a *PostgresQueries) ListHostKeys(ctx context.Context, serverID domain.ServerID) ([]domain.HostKey, error) {
	rows, err := a.q.ListServerHostKeys(ctx, int64(serverID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.HostKey, 0, len(rows))
	for _, h := range rows {
		out = append(out, pgHostKey(h))
	}
	return out, nil
}

func (a *PostgresQueries) CreateHostKey(ctx context.Context, p CreateHostKeyParams) (domain.HostKey, error) {
	h, err := a.q.CreateServerHostKey(ctx, pg.CreateServerHostKeyParams{
		ServerID: int64(p.ServerID), Algorithm: p.Algorithm, Fingerprint: p.Fingerprint,
		PublicKey: p.PublicKey, State: string(p.State),
		TrustedAt: p.TrustedAt, TrustedBy: optID(p.TrustedBy),
	})
	return pgHostKey(h), err
}

func (a *PostgresQueries) UpdateHostKeyState(ctx context.Context, p UpdateHostKeyStateParams) error {
	return a.q.UpdateHostKeyState(ctx, pg.UpdateHostKeyStateParams{
		ID: p.ID, State: string(p.State), TrustedAt: p.TrustedAt, TrustedBy: optID(p.TrustedBy),
	})
}

func (a *PostgresQueries) DeleteHostKeys(ctx context.Context, serverID domain.ServerID) error {
	return a.q.DeleteServerHostKeys(ctx, int64(serverID))
}

// --- tags -------------------------------------------------------------------

func (a *PostgresQueries) UpsertTag(ctx context.Context, name string) (domain.Tag, error) {
	t, err := a.q.UpsertTag(ctx, name)
	if err != nil {
		return domain.Tag{}, err
	}
	return domain.Tag{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt}, nil
}

func (a *PostgresQueries) ListTags(ctx context.Context) ([]domain.Tag, error) {
	rows, err := a.q.ListTags(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Tag, 0, len(rows))
	for _, t := range rows {
		out = append(out, domain.Tag{ID: t.ID, Name: t.Name, ServerCount: t.ServerCount, CreatedAt: t.CreatedAt})
	}
	return out, nil
}

func (a *PostgresQueries) AddServerTag(ctx context.Context, serverID domain.ServerID, tagID int64) error {
	return a.q.AddServerTag(ctx, pg.AddServerTagParams{ServerID: int64(serverID), TagID: tagID})
}

func (a *PostgresQueries) ClearServerTags(ctx context.Context, serverID domain.ServerID) error {
	return a.q.ClearServerTags(ctx, int64(serverID))
}

func (a *PostgresQueries) DeleteOrphanTags(ctx context.Context) (int64, error) {
	return a.q.DeleteOrphanTags(ctx)
}

// --- per-server permissions -------------------------------------------------

func (a *PostgresQueries) ListServerPermissions(ctx context.Context, userID domain.UserID, serverID domain.ServerID) ([]domain.Permission, error) {
	names, err := a.q.ListServerPermissions(ctx, pg.ListServerPermissionsParams{
		UserID: int64(userID), ServerID: int64(serverID),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Permission, 0, len(names))
	for _, n := range names {
		out = append(out, domain.Permission(n))
	}
	return out, nil
}

func (a *PostgresQueries) GrantServerPermission(ctx context.Context, p GrantServerPermissionParams) error {
	perm, err := a.q.GetPermissionByName(ctx, string(p.Permission))
	if err != nil {
		return err
	}
	return a.q.GrantServerPermission(ctx, pg.GrantServerPermissionParams{
		UserID: int64(p.UserID), ServerID: int64(p.ServerID),
		PermissionID: perm.ID, GrantedBy: optID(p.GrantedBy),
	})
}

func (a *PostgresQueries) ClearServerPermissions(ctx context.Context, userID domain.UserID, serverID domain.ServerID) error {
	return a.q.ClearServerPermissions(ctx, pg.ClearServerPermissionsParams{
		UserID: int64(userID), ServerID: int64(serverID),
	})
}

func (a *PostgresQueries) ListAccessibleServerIDs(ctx context.Context, userID domain.UserID) ([]domain.ServerID, error) {
	ids, err := a.q.ListAccessibleServerIDs(ctx, int64(userID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.ServerID, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.ServerID(id))
	}
	return out, nil
}

func (a *PostgresQueries) ListServerPermissionGrants(ctx context.Context, userID domain.UserID) ([]ServerGrant, error) {
	rows, err := a.q.ListServerPermissionGrants(ctx, int64(userID))
	if err != nil {
		return nil, err
	}
	out := make([]ServerGrant, 0, len(rows))
	for _, r := range rows {
		out = append(out, ServerGrant{ServerID: domain.ServerID(r.ServerID), Permission: domain.Permission(r.Name)})
	}
	return out, nil
}

// --- audit ------------------------------------------------------------------

func pgAuditEvent(x pg.AuditLog) domain.AuditEvent {
	out := domain.AuditEvent{
		ID:         x.ID,
		Timestamp:  x.Ts,
		ActorName:  x.ActorName,
		Action:     x.Action,
		Target:     x.Target,
		ServerName: x.ServerName,
		Result:     domain.AuditResult(x.Result),
		RequestID:  x.RequestID,
		IP:         x.Ip,
		UserAgent:  x.UserAgent,
		Metadata:   decodeMetadata(x.Metadata),
	}
	if x.ActorID != nil {
		id := domain.UserID(*x.ActorID)
		out.ActorID = &id
	}
	if x.ServerID != nil {
		id := domain.ServerID(*x.ServerID)
		out.ServerID = &id
	}
	return out
}

func decodeMetadata(raw []byte) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func pgAuditParams(p InsertAuditParams) pg.InsertAuditLogParams {
	return pg.InsertAuditLogParams{
		ActorID: optID(p.ActorID), ActorName: p.ActorName, Action: p.Action, Target: p.Target,
		ServerID: optServerID(p.ServerID), ServerName: p.ServerName, Result: string(p.Result),
		RequestID: p.RequestID, Ip: p.IP, UserAgent: p.UserAgent, Metadata: jsonOr(p.Metadata, "{}"),
	}
}

func (a *PostgresQueries) InsertAudit(ctx context.Context, p InsertAuditParams) (domain.AuditEvent, error) {
	e, err := a.q.InsertAuditLog(ctx, pgAuditParams(p))
	return pgAuditEvent(e), err
}

// InsertAuditTx writes an audit record inside the caller's transaction, so a
// security-sensitive change and its audit entry commit together (or not at
// all). If the audit write fails, the change fails with it.
func (a *PostgresQueries) InsertAuditTx(ctx context.Context, tx *sql.Tx, p InsertAuditParams) (domain.AuditEvent, error) {
	adapter := store.NewSqlTxAdapter(tx)
	q := pg.New(adapter)
	e, err := q.InsertAuditLog(ctx, pgAuditParams(p))
	return pgAuditEvent(e), err
}

func pgAuditQuery(p AuditQueryParams) pg.ListAuditLogsParams {
	return pg.ListAuditLogsParams{
		Limit: i32(p.Limit), Offset: i32(p.Offset),
		ActorID: optID(p.ActorID), ServerID: optServerID(p.ServerID),
		Action: nullString(p.Action), Result: nullString(p.Result), Ip: nullString(p.IP),
		RequestID: nullString(p.RequestID),
		FromTs:    nullTime(p.From), ToTs: nullTime(p.To), Search: nullString(p.Search),
	}
}

func (a *PostgresQueries) ListAudit(ctx context.Context, p AuditQueryParams) ([]domain.AuditEvent, error) {
	rows, err := a.q.ListAuditLogs(ctx, pgAuditQuery(p))
	if err != nil {
		return nil, err
	}
	out := make([]domain.AuditEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, pgAuditEvent(r))
	}
	return out, nil
}

func (a *PostgresQueries) CountAudit(ctx context.Context, p AuditQueryParams) (int64, error) {
	return a.q.CountAuditLogs(ctx, pg.CountAuditLogsParams{
		ActorID: optID(p.ActorID), ServerID: optServerID(p.ServerID),
		Action: nullString(p.Action), Result: nullString(p.Result), Ip: nullString(p.IP),
		RequestID: nullString(p.RequestID),
		FromTs:    nullTime(p.From), ToTs: nullTime(p.To), Search: nullString(p.Search),
	})
}

func (a *PostgresQueries) CountSecurityEvents(ctx context.Context, since time.Time) (int64, error) {
	return a.q.CountSecurityEvents(ctx, since)
}

// DeleteAuditBefore is the single permitted deletion path for audit rows.
// Callers record an AUDIT_PRUNED event so pruning is itself visible.
func (a *PostgresQueries) DeleteAuditBefore(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteAuditBefore(ctx, before)
}

// --- jobs -------------------------------------------------------------------

func pgJob(j pg.Job) domain.Job {
	out := domain.Job{
		ID:          j.ID,
		Kind:        j.Kind,
		Status:      domain.JobStatus(j.Status),
		Priority:    int(j.Priority),
		Attempts:    int(j.Attempts),
		MaxAttempts: int(j.MaxAttempts),
		RunAt:       j.RunAt,
		LockedBy:    ptrFromNullString(j.LockedBy),
		LockedAt:    ptrFromNullTime(j.LockedAt),
		Payload:     j.Payload,
		Progress:    j.Progress,
		LastError:   j.LastError,
		CreatedAt:   j.CreatedAt,
		UpdatedAt:   j.UpdatedAt,
		FinishedAt:  j.FinishedAt,
		DedupeKey:   j.DedupeKey,
	}
	if j.CreatedBy != nil {
		id := domain.UserID(*j.CreatedBy)
		out.CreatedBy = &id
	}
	if j.ServerID != nil {
		id := domain.ServerID(*j.ServerID)
		out.ServerID = &id
	}
	return out
}

func (a *PostgresQueries) EnqueueJob(ctx context.Context, p EnqueueJobParams) (domain.Job, error) {
	j, err := a.q.EnqueueJob(ctx, pg.EnqueueJobParams{
		Kind: p.Kind, Priority: i32(int64(p.Priority)), MaxAttempts: i32(int64(p.MaxAttempts)),
		RunAt: p.RunAt, Payload: jsonOr(p.Payload, "{}"),
		CreatedBy: optID(p.CreatedBy), ServerID: optServerID(p.ServerID), DedupeKey: p.DedupeKey,
	})
	return pgJob(j), err
}

func (a *PostgresQueries) GetJob(ctx context.Context, id int64) (domain.Job, error) {
	j, err := a.q.GetJob(ctx, id)
	return pgJob(j), err
}

func (a *PostgresQueries) ListJobs(ctx context.Context, p ListJobsParams) ([]domain.Job, error) {
	rows, err := a.q.ListJobs(ctx, pg.ListJobsParams{
		Limit: i32(p.Limit), Offset: i32(p.Offset),
		Status: nullString(p.Status), Kind: nullString(p.Kind), ServerID: optServerID(p.ServerID), CreatedBy: optID(p.CreatedBy),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Job, 0, len(rows))
	for _, j := range rows {
		out = append(out, pgJob(j))
	}
	return out, nil
}

func (a *PostgresQueries) CountJobs(ctx context.Context, p ListJobsParams) (int64, error) {
	return a.q.CountJobs(ctx, pg.CountJobsParams{
		Status: nullString(p.Status), Kind: nullString(p.Kind), ServerID: optServerID(p.ServerID), CreatedBy: optID(p.CreatedBy),
	})
}

func (a *PostgresQueries) CountJobsByStatus(ctx context.Context) (map[string]int64, error) {
	rows, err := a.q.CountJobsByStatus(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Status] = r.Count
	}
	return out, nil
}

// ClaimJob is critical-path. It is an UPDATE ... RETURNING, so the claim
// commits before the row is scanned; an error from this method must mean the
// job was NOT claimed. The generated row types scan cleanly on both dialects
// precisely because of the JSON []byte and timestamp overrides in sqlc.yaml.
func (a *PostgresQueries) ClaimJob(ctx context.Context, workerID string) (domain.Job, error) {
	j, err := a.q.ClaimJob(ctx, &workerID)
	return pgJob(j), err
}

func (a *PostgresQueries) ClaimJobByKind(ctx context.Context, workerID, kind string) (domain.Job, error) {
	j, err := a.q.ClaimJobByKind(ctx, pg.ClaimJobByKindParams{
		LockedBy: &workerID, Kind: kind,
	})
	return pgJob(j), err
}

func (a *PostgresQueries) CompleteJob(ctx context.Context, id int64) error {
	return a.q.CompleteJob(ctx, id)
}

func (a *PostgresQueries) UpdateJobProgress(ctx context.Context, id int64, progress float64) error {
	return a.q.UpdateJobProgress(ctx, pg.UpdateJobProgressParams{ID: id, Progress: progress})
}

func (a *PostgresQueries) HeartbeatJob(ctx context.Context, id int64) error {
	return a.q.HeartbeatJob(ctx, id)
}

func (a *PostgresQueries) FailJob(ctx context.Context, id int64, runAt time.Time, errMsg string) error {
	return a.q.FailJob(ctx, pg.FailJobParams{ID: id, RunAt: runAt, LastError: errMsg})
}

func (a *PostgresQueries) DeadJob(ctx context.Context, id int64, errMsg string) error {
	return a.q.DeadJob(ctx, pg.DeadJobParams{ID: id, LastError: errMsg})
}

func (a *PostgresQueries) CancelJob(ctx context.Context, id int64) error {
	return a.q.CancelJob(ctx, id)
}

func (a *PostgresQueries) RequeueJob(ctx context.Context, id int64, runAt time.Time) error {
	return a.q.RequeueJob(ctx, pg.RequeueJobParams{ID: id, RunAt: runAt})
}

func (a *PostgresQueries) ListStaleJobs(ctx context.Context, olderThan time.Time) ([]domain.Job, error) {
	rows, err := a.q.ListStaleJobs(ctx, &olderThan)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Job, 0, len(rows))
	for _, j := range rows {
		out = append(out, pgJob(j))
	}
	return out, nil
}

func (a *PostgresQueries) PromoteRetryingJobs(ctx context.Context) (int64, error) {
	return a.q.PromoteRetryingJobs(ctx)
}

func (a *PostgresQueries) DeleteFinishedJobsBefore(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteFinishedJobsBefore(ctx, &before)
}

// --- metrics ----------------------------------------------------------------

func (a *PostgresQueries) UpsertMetricSample(ctx context.Context, s domain.MetricSample) error {
	return a.q.UpsertMetricSample(ctx, pg.UpsertMetricSampleParams{
		ServerID: int64(s.ServerID), Ts: s.Timestamp,
		CpuPct: s.CPUPct, Load1: s.Load1, Load5: s.Load5, Load15: s.Load15,
		MemTotal: s.MemTotal, MemUsed: s.MemUsed, MemAvailable: s.MemAvailable,
		MemCached: s.MemCached, MemBuffers: s.MemBuffers,
		SwapTotal: s.SwapTotal, SwapUsed: s.SwapUsed,
		NetRxBytes: s.NetRxBytes, NetTxBytes: s.NetTxBytes,
		DiskReadBytes: s.DiskReadBytes, DiskWriteBytes: s.DiskWriteBytes,
		UptimeSeconds: s.UptimeSeconds, ProcessCount: s.ProcessCount,
	})
}

func pgMetric(m pg.MetricSample) domain.MetricSample {
	return domain.MetricSample{
		ServerID:       domain.ServerID(m.ServerID),
		Timestamp:      m.Ts,
		CPUPct:         m.CpuPct,
		Load1:          m.Load1,
		Load5:          m.Load5,
		Load15:         m.Load15,
		MemTotal:       m.MemTotal,
		MemUsed:        m.MemUsed,
		MemAvailable:   m.MemAvailable,
		MemCached:      m.MemCached,
		MemBuffers:     m.MemBuffers,
		SwapTotal:      m.SwapTotal,
		SwapUsed:       m.SwapUsed,
		NetRxBytes:     m.NetRxBytes,
		NetTxBytes:     m.NetTxBytes,
		DiskReadBytes:  m.DiskReadBytes,
		DiskWriteBytes: m.DiskWriteBytes,
		UptimeSeconds:  m.UptimeSeconds,
		ProcessCount:   m.ProcessCount,
	}
}

func (a *PostgresQueries) GetLatestMetricSample(ctx context.Context, serverID domain.ServerID) (domain.MetricSample, error) {
	m, err := a.q.GetLatestMetricSample(ctx, int64(serverID))
	return pgMetric(m), err
}

func (a *PostgresQueries) ListMetricSamples(ctx context.Context, p MetricRangeParams) ([]domain.MetricSample, error) {
	rows, err := a.q.ListMetricSamples(ctx, pg.ListMetricSamplesParams{
		ServerID: int64(p.ServerID), Ts: p.From, Ts_2: p.To, Limit: i32(p.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, m := range rows {
		out = append(out, pgMetric(m))
	}
	return out, nil
}

func pgFilesystem(f pg.MetricFilesystem) domain.Filesystem {
	return domain.Filesystem{
		ServerID:   domain.ServerID(f.ServerID),
		Timestamp:  f.Ts,
		MountPoint: f.MountPoint,
		Device:     f.Device,
		FSType:     f.FsType,
		TotalBytes: f.TotalBytes,
		UsedBytes:  f.UsedBytes,
		AvailBytes: f.AvailBytes,
		UsedPct:    f.UsedPct,
	}
}

func (a *PostgresQueries) UpsertMetricFilesystem(ctx context.Context, f domain.Filesystem) error {
	return a.q.UpsertMetricFilesystem(ctx, pg.UpsertMetricFilesystemParams{
		ServerID: int64(f.ServerID), Ts: f.Timestamp, MountPoint: f.MountPoint,
		Device: f.Device, FsType: f.FSType,
		TotalBytes: f.TotalBytes, UsedBytes: f.UsedBytes, AvailBytes: f.AvailBytes, UsedPct: f.UsedPct,
	})
}

func (a *PostgresQueries) ListLatestFilesystems(ctx context.Context, serverID domain.ServerID) ([]domain.Filesystem, error) {
	rows, err := a.q.ListLatestFilesystems(ctx, int64(serverID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Filesystem, 0, len(rows))
	for _, f := range rows {
		out = append(out, pgFilesystem(f))
	}
	return out, nil
}

func (a *PostgresQueries) DeleteMetricSamplesBefore(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteMetricSamplesBefore(ctx, before)
}

// --- misc -------------------------------------------------------------------

func (a *PostgresQueries) Ping(ctx context.Context) error {
	_, err := a.q.Ping(ctx)
	return err
}

var _ Queries = (*PostgresQueries)(nil)
