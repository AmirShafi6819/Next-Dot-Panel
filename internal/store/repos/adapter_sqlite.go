package repos

import (
	"context"
	"database/sql"
	"time"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// SQLiteQueries adapts the generated SQLite query set onto the neutral
// Queries interface.
//
// SQLite emits int64 counters and LIMIT/OFFSET natively and pointer types for
// nullable columns (emit_pointers_for_null_types), so conversions here are
// mostly pass-through. The conversion helpers (optID, optServerID, i32,
// jsonOr, nullString, nullTime) are shared with the Postgres adapter.
type SQLiteQueries struct {
	q *lite.Queries
}

// NewSQLiteQueries wraps a generated SQLite query set.
func NewSQLiteQueries(q *lite.Queries) *SQLiteQueries {
	return &SQLiteQueries{q: q}
}

// NewSQLiteTxQueries returns a query set bound to a transaction, so a change
// and its audit record commit or roll back together.
func NewSQLiteTxQueries(tx *sql.Tx) *SQLiteQueries {
	base := &lite.Queries{}
	return &SQLiteQueries{q: base.WithTx(tx)}
}

// --- users -----------------------------------------------------------------

func liteUser(u lite.User) domain.User {
	out := domain.User{
		ID:                 domain.UserID(u.ID),
		Username:           u.Username,
		PasswordHash:       u.PasswordHash,
		DisplayName:        u.DisplayName,
		IsActive:           u.IsActive,
		IsBootstrapDefault: u.IsBootstrapDefault,
		MustChangePassword: u.MustChangePassword,
		LastLoginAt:        parseSQLiteTimePtrStr(u.LastLoginAt),
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
		DeletedAt:          parseSQLiteTimePtrStr(u.DeletedAt),
		Version:            u.Version,
	}
	return out
}

func (a *SQLiteQueries) CreateUser(ctx context.Context, p CreateUserParams) (domain.User, error) {
	u, err := a.q.CreateUser(ctx, lite.CreateUserParams{
		Username:           p.Username,
		PasswordHash:       p.PasswordHash,
		DisplayName:        p.DisplayName,
		IsActive:           p.IsActive,
		IsBootstrapDefault: p.IsBootstrapDefault,
		MustChangePassword: p.MustChangePassword,
	})
	return liteUser(u), err
}

func (a *SQLiteQueries) GetUserByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	u, err := a.q.GetUserByID(ctx, int64(id))
	return liteUser(u), err
}

func (a *SQLiteQueries) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	u, err := a.q.GetUserByUsername(ctx, username)
	return liteUser(u), err
}

func (a *SQLiteQueries) ListUsers(ctx context.Context, p ListUsersParams) ([]domain.User, error) {
	rows, err := a.q.ListUsers(ctx, lite.ListUsersParams{
		Limit: p.Limit, Offset: p.Offset,
		Search: p.Search, IsActive: p.IsActive,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.User, 0, len(rows))
	for _, u := range rows {
		out = append(out, liteUser(u))
	}
	return out, nil
}

func (a *SQLiteQueries) CountUsers(ctx context.Context, p CountUsersParams) (int64, error) {
	return a.q.CountUsers(ctx, lite.CountUsersParams{Search: p.Search, IsActive: p.IsActive})
}

func (a *SQLiteQueries) UpdateUser(ctx context.Context, p UpdateUserParams) (domain.User, error) {
	u, err := a.q.UpdateUser(ctx, lite.UpdateUserParams{
		ID: int64(p.ID), DisplayName: p.DisplayName, IsActive: p.IsActive, Version: p.Version,
	})
	return liteUser(u), err
}

func (a *SQLiteQueries) SetUserPassword(ctx context.Context, p SetUserPasswordParams) (domain.User, error) {
	u, err := a.q.SetUserPassword(ctx, lite.SetUserPasswordParams{
		ID: int64(p.ID), PasswordHash: p.PasswordHash, MustChangePassword: p.MustChange,
	})
	return liteUser(u), err
}

func (a *SQLiteQueries) RecordUserLogin(ctx context.Context, id domain.UserID) error {
	return a.q.RecordUserLogin(ctx, int64(id))
}

func (a *SQLiteQueries) SoftDeleteUser(ctx context.Context, id domain.UserID) error {
	return a.q.SoftDeleteUser(ctx, int64(id))
}

func (a *SQLiteQueries) CountAllUsers(ctx context.Context) (int64, error) {
	return a.q.CountAllUsers(ctx)
}

func (a *SQLiteQueries) CountActiveAdmins(ctx context.Context) (int64, error) {
	return a.q.CountActiveAdmins(ctx)
}

func (a *SQLiteQueries) CountUsersWithDefaultCredentials(ctx context.Context) (int64, error) {
	return a.q.CountUsersWithDefaultCredentials(ctx)
}

// --- roles and permissions --------------------------------------------------

func (a *SQLiteQueries) CreateRole(ctx context.Context, p CreateRoleParams) (domain.Role, error) {
	r, err := a.q.CreateRole(ctx, lite.CreateRoleParams{
		Name: p.Name, Description: p.Description, IsSystem: p.IsSystem,
	})
	if err != nil {
		return domain.Role{}, err
	}
	return liteRole(r), nil
}

func liteRole(r lite.Role) domain.Role {
	return domain.Role{
		ID:          domain.RoleID(r.ID),
		Name:        r.Name,
		Description: r.Description,
		IsSystem:    r.IsSystem,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func (a *SQLiteQueries) GetRoleByName(ctx context.Context, name string) (domain.Role, error) {
	r, err := a.q.GetRoleByName(ctx, name)
	return liteRole(r), err
}

func (a *SQLiteQueries) GetRoleByID(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	r, err := a.q.GetRoleByID(ctx, int64(id))
	return liteRole(r), err
}

func (a *SQLiteQueries) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := a.q.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(rows))
	for _, r := range rows {
		out = append(out, liteRole(r))
	}
	return out, nil
}

func (a *SQLiteQueries) UpdateRole(ctx context.Context, p UpdateRoleParams) (domain.Role, error) {
	r, err := a.q.UpdateRole(ctx, lite.UpdateRoleParams{ID: int64(p.ID), Name: p.Name, Description: p.Description})
	return liteRole(r), err
}

func (a *SQLiteQueries) DeleteRole(ctx context.Context, id domain.RoleID) error {
	return a.q.DeleteRole(ctx, int64(id))
}

func (a *SQLiteQueries) ListUserRoles(ctx context.Context, userID domain.UserID) ([]domain.Role, error) {
	rows, err := a.q.ListUserRoles(ctx, int64(userID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(rows))
	for _, r := range rows {
		out = append(out, liteRole(r))
	}
	return out, nil
}

func (a *SQLiteQueries) AddUserRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error {
	return a.q.AddUserRole(ctx, lite.AddUserRoleParams{UserID: int64(userID), RoleID: int64(roleID)})
}

func (a *SQLiteQueries) RemoveUserRole(ctx context.Context, userID domain.UserID, roleID domain.RoleID) error {
	return a.q.RemoveUserRole(ctx, lite.RemoveUserRoleParams{UserID: int64(userID), RoleID: int64(roleID)})
}

func (a *SQLiteQueries) ClearUserRoles(ctx context.Context, userID domain.UserID) error {
	return a.q.ClearUserRoles(ctx, int64(userID))
}

func (a *SQLiteQueries) CreatePermission(ctx context.Context, p CreatePermissionParams) error {
	_, err := a.q.CreatePermission(ctx, lite.CreatePermissionParams{
		Name: string(p.Name), Description: p.Description,
	})
	return err
}

func (a *SQLiteQueries) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
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

func (a *SQLiteQueries) ListUserPermissions(ctx context.Context, userID domain.UserID) ([]domain.Permission, error) {
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

func (a *SQLiteQueries) ListRolePermissions(ctx context.Context, roleID domain.RoleID) ([]domain.Permission, error) {
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

func (a *SQLiteQueries) AddRolePermission(ctx context.Context, roleID domain.RoleID, perm domain.Permission) error {
	// Permissions are referenced by id, resolved from the name.
	p, err := a.q.GetPermissionByName(ctx, string(perm))
	if err != nil {
		return err
	}
	return a.q.AddRolePermission(ctx, lite.AddRolePermissionParams{RoleID: int64(roleID), PermissionID: p.ID})
}

func (a *SQLiteQueries) ClearRolePermissions(ctx context.Context, roleID domain.RoleID) error {
	return a.q.ClearRolePermissions(ctx, int64(roleID))
}

// --- sessions ---------------------------------------------------------------

func liteSession(s lite.Session) domain.Session {
	return domain.Session{
		ID:         s.ID,
		UserID:     domain.UserID(s.UserID),
		TokenHash:  s.TokenHash,
		IP:         s.Ip,
		UserAgent:  s.UserAgent,
		CreatedAt:  s.CreatedAt,
		LastSeenAt: s.LastSeenAt,
		ExpiresAt:  s.ExpiresAt,
		RevokedAt:  parseSQLiteTimePtrStr(s.RevokedAt),
	}
}

func (a *SQLiteQueries) CreateSession(ctx context.Context, p CreateSessionParams) (domain.Session, error) {
	s, err := a.q.CreateSession(ctx, lite.CreateSessionParams{
		ID: p.ID, UserID: int64(p.UserID), TokenHash: p.TokenHash,
		Ip: p.IP, UserAgent: p.UserAgent, ExpiresAt: p.ExpiresAt,
	})
	return liteSession(s), err
}

func (a *SQLiteQueries) GetSessionByTokenHash(ctx context.Context, hash []byte) (domain.Session, error) {
	s, err := a.q.GetSessionByTokenHash(ctx, hash)
	return liteSession(s), err
}

func (a *SQLiteQueries) GetSessionByID(ctx context.Context, id string) (domain.Session, error) {
	s, err := a.q.GetSessionByID(ctx, id)
	return liteSession(s), err
}

func (a *SQLiteQueries) ListUserSessions(ctx context.Context, userID domain.UserID) ([]domain.Session, error) {
	rows, err := a.q.ListUserSessions(ctx, int64(userID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, 0, len(rows))
	for _, s := range rows {
		out = append(out, liteSession(s))
	}
	return out, nil
}

func (a *SQLiteQueries) ListAllSessions(ctx context.Context, p PageParams) ([]domain.Session, error) {
	rows, err := a.q.ListAllSessions(ctx, lite.ListAllSessionsParams{Limit: p.Limit, Offset: p.Offset})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, 0, len(rows))
	for _, s := range rows {
		out = append(out, domain.Session{
			ID: s.ID, UserID: domain.UserID(s.UserID), TokenHash: s.TokenHash,
			IP: s.Ip, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt,
			LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt, RevokedAt: parseSQLiteTimePtrStr(s.RevokedAt),
			Username: s.Username,
		})
	}
	return out, nil
}

func (a *SQLiteQueries) CountActiveSessions(ctx context.Context) (int64, error) {
	return a.q.CountActiveSessions(ctx)
}

func (a *SQLiteQueries) TouchSession(ctx context.Context, id string) error {
	return a.q.TouchSession(ctx, id)
}

func (a *SQLiteQueries) RevokeSession(ctx context.Context, id string) error {
	return a.q.RevokeSession(ctx, id)
}

func (a *SQLiteQueries) RevokeUserSessions(ctx context.Context, userID domain.UserID) (int64, error) {
	return a.q.RevokeUserSessions(ctx, int64(userID))
}

func (a *SQLiteQueries) RevokeUserSessionsExcept(ctx context.Context, userID domain.UserID, keep string) (int64, error) {
	return a.q.RevokeUserSessionsExcept(ctx, lite.RevokeUserSessionsExceptParams{UserID: int64(userID), ID: keep})
}

func (a *SQLiteQueries) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteExpiredSessions(ctx, before)
}

// --- login history ----------------------------------------------------------

func liteLoginAttempt(l lite.LoginHistory) domain.LoginAttempt {
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

func (a *SQLiteQueries) InsertLoginAttempt(ctx context.Context, p InsertLoginAttemptParams) (domain.LoginAttempt, error) {
	l, err := a.q.InsertLoginHistory(ctx, lite.InsertLoginHistoryParams{
		UserID: optID(p.UserID), Username: p.Username, Ip: p.IP, UserAgent: p.UserAgent,
		Success: p.Success, FailureReason: p.FailureReason, SessionID: p.SessionID,
	})
	return liteLoginAttempt(l), err
}

func (a *SQLiteQueries) ListLoginHistory(ctx context.Context, p LoginHistoryParams) ([]domain.LoginAttempt, error) {
	rows, err := a.q.ListLoginHistory(ctx, lite.ListLoginHistoryParams{
		Limit: p.Limit, Offset: p.Offset,
		UserID: optIDValue(p.UserID), Ip: p.IP, Success: p.Success, FromTs: p.From, ToTs: p.To,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.LoginAttempt, 0, len(rows))
	for _, l := range rows {
		out = append(out, liteLoginAttempt(l))
	}
	return out, nil
}

func (a *SQLiteQueries) CountLoginHistory(ctx context.Context, p LoginHistoryParams) (int64, error) {
	return a.q.CountLoginHistory(ctx, lite.CountLoginHistoryParams{
		UserID: optIDValue(p.UserID), Ip: p.IP, Success: p.Success, FromTs: p.From, ToTs: p.To,
	})
}

func (a *SQLiteQueries) CountRecentLoginFailures(ctx context.Context, username string, since time.Time) (int64, error) {
	return a.q.CountRecentLoginFailures(ctx, lite.CountRecentLoginFailuresParams{Username: username, Ts: since})
}

func (a *SQLiteQueries) CountRecentLoginFailuresByIP(ctx context.Context, ip string, since time.Time) (int64, error) {
	return a.q.CountRecentLoginFailuresByIP(ctx, lite.CountRecentLoginFailuresByIPParams{Ip: ip, Ts: since})
}

// --- servers ----------------------------------------------------------------

func liteServer(s lite.Server) domain.Server {
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
		LastSeenAt:   parseSQLiteTimePtrStr(s.LastSeenAt),
		LastErrorAt:  parseSQLiteTimePtrStr(s.LastErrorAt),
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
		Version:      s.Version,
	}
}

func (a *SQLiteQueries) CreateServer(ctx context.Context, p CreateServerParams) (domain.Server, error) {
	s, err := a.q.CreateServer(ctx, lite.CreateServerParams{
		Name: p.Name, TargetType: string(p.TargetType), Host: p.Host, Port: int64(p.Port),
		Username: p.Username, AuthMethod: string(p.AuthMethod), HostKeyPolicy: string(p.HostKeyPolicy),
		Tags: jsonOr(p.Tags, "[]"), Notes: p.Notes, IsFavourite: p.IsFavourite,
	})
	return liteServer(s), err
}

func (a *SQLiteQueries) GetServerByID(ctx context.Context, id domain.ServerID) (domain.Server, error) {
	s, err := a.q.GetServerByID(ctx, int64(id))
	return liteServer(s), err
}

func (a *SQLiteQueries) GetServerByName(ctx context.Context, name string) (domain.Server, error) {
	s, err := a.q.GetServerByName(ctx, name)
	return liteServer(s), err
}

func (a *SQLiteQueries) ListServers(ctx context.Context, p ListServersParams) ([]domain.Server, error) {
	rows, err := a.q.ListServers(ctx, lite.ListServersParams{
		Limit: p.Limit, Offset: p.Offset,
		Search: nullString(p.Search), Status: nullString(p.Status), TargetType: nullString(p.TargetType), Tag: nullString(p.Tag),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Server, 0, len(rows))
	for _, s := range rows {
		out = append(out, liteServer(s))
	}
	return out, nil
}

func (a *SQLiteQueries) CountServers(ctx context.Context, p CountServersParams) (int64, error) {
	return a.q.CountServers(ctx, lite.CountServersParams{
		Search: nullString(p.Search), Status: nullString(p.Status), TargetType: nullString(p.TargetType), Tag: nullString(p.Tag),
	})
}

func (a *SQLiteQueries) ListAllServers(ctx context.Context) ([]domain.Server, error) {
	rows, err := a.q.ListAllServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Server, 0, len(rows))
	for _, s := range rows {
		out = append(out, liteServer(s))
	}
	return out, nil
}

func (a *SQLiteQueries) CountServersByStatus(ctx context.Context) (map[string]int64, error) {
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

func (a *SQLiteQueries) UpdateServer(ctx context.Context, p UpdateServerParams) (domain.Server, error) {
	s, err := a.q.UpdateServer(ctx, lite.UpdateServerParams{
		ID: int64(p.ID), Name: p.Name, Host: p.Host, Port: int64(p.Port),
		Username: p.Username, AuthMethod: string(p.AuthMethod), HostKeyPolicy: string(p.HostKeyPolicy),
		Tags: jsonOr(p.Tags, "[]"), Notes: p.Notes, IsFavourite: p.IsFavourite, Version: p.Version,
	})
	return liteServer(s), err
}

func (a *SQLiteQueries) UpdateServerStatus(ctx context.Context, p UpdateServerStatusParams) (domain.Server, error) {
	s, err := a.q.UpdateServerStatus(ctx, lite.UpdateServerStatusParams{
		ID: int64(p.ID), Status: string(p.Status), StatusDetail: p.Detail,
	})
	return liteServer(s), err
}

func (a *SQLiteQueries) UpdateServerSystemInfo(ctx context.Context, p UpdateServerSystemInfoParams) error {
	return a.q.UpdateServerSystemInfo(ctx, lite.UpdateServerSystemInfoParams{
		ID: int64(p.ID), Os: p.OS, Kernel: p.Kernel, Arch: p.Arch,
	})
}

func (a *SQLiteQueries) DeleteServer(ctx context.Context, id domain.ServerID) error {
	return a.q.DeleteServer(ctx, int64(id))
}

func (a *SQLiteQueries) ServerNameExists(ctx context.Context, name string, exclude domain.ServerID) (bool, error) {
	n, err := a.q.ServerNameExists(ctx, lite.ServerNameExistsParams{Name: name, ID: int64(exclude)})
	return n != 0, err
}

// --- credentials ------------------------------------------------------------

func liteCredential(c lite.ServerCredential) domain.Credential {
	return domain.Credential{
		ID:         domain.CredentialID(c.ID),
		ServerID:   domain.ServerID(c.ServerID),
		Kind:       domain.AuthMethod(c.Kind),
		Ciphertext: c.Ciphertext,
		Version:    c.Version,
		CreatedAt:  c.CreatedAt,
		RotatedAt:  parseSQLiteTimePtrStr(c.RotatedAt),
	}
}

func (a *SQLiteQueries) CreateCredential(ctx context.Context, p CreateCredentialParams) (domain.Credential, error) {
	c, err := a.q.CreateServerCredential(ctx, lite.CreateServerCredentialParams{
		ServerID: int64(p.ServerID), Kind: string(p.Kind), Ciphertext: p.Ciphertext, Version: p.Version,
	})
	return liteCredential(c), err
}

func (a *SQLiteQueries) GetCredential(ctx context.Context, serverID domain.ServerID) (domain.Credential, error) {
	c, err := a.q.GetServerCredential(ctx, int64(serverID))
	return liteCredential(c), err
}

func (a *SQLiteQueries) RotateCredential(ctx context.Context, p CreateCredentialParams) (domain.Credential, error) {
	c, err := a.q.RotateServerCredential(ctx, lite.RotateServerCredentialParams{
		ServerID: int64(p.ServerID), Kind: string(p.Kind), Ciphertext: p.Ciphertext,
	})
	return liteCredential(c), err
}

func (a *SQLiteQueries) DeleteServerCredentials(ctx context.Context, serverID domain.ServerID) error {
	return a.q.DeleteServerCredentials(ctx, int64(serverID))
}

func (a *SQLiteQueries) ListCredentialCiphertexts(ctx context.Context) ([]CredentialCiphertext, error) {
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

func (a *SQLiteQueries) UpdateCredentialCiphertext(ctx context.Context, id domain.CredentialID, ciphertext []byte) error {
	return a.q.UpdateCredentialCiphertext(ctx, lite.UpdateCredentialCiphertextParams{
		ID: int64(id), Ciphertext: ciphertext,
	})
}

// --- host keys --------------------------------------------------------------

func liteHostKey(h lite.ServerHostKey) domain.HostKey {
	out := domain.HostKey{
		ID:          h.ID,
		ServerID:    domain.ServerID(h.ServerID),
		Algorithm:   h.Algorithm,
		Fingerprint: h.Fingerprint,
		PublicKey:   h.PublicKey,
		State:       domain.HostKeyState(h.State),
		FirstSeen:   h.FirstSeen,
		TrustedAt:   parseSQLiteTimePtrStr(h.TrustedAt),
	}
	if h.TrustedBy != nil {
		id := domain.UserID(*h.TrustedBy)
		out.TrustedBy = &id
	}
	return out
}

func (a *SQLiteQueries) GetHostKey(ctx context.Context, serverID domain.ServerID) (domain.HostKey, error) {
	h, err := a.q.GetServerHostKey(ctx, int64(serverID))
	return liteHostKey(h), err
}

func (a *SQLiteQueries) GetHostKeyByFingerprint(ctx context.Context, serverID domain.ServerID, fingerprint string) (domain.HostKey, error) {
	h, err := a.q.GetServerHostKeyByFingerprint(ctx, lite.GetServerHostKeyByFingerprintParams{
		ServerID: int64(serverID), Fingerprint: fingerprint,
	})
	return liteHostKey(h), err
}

func (a *SQLiteQueries) ListHostKeys(ctx context.Context, serverID domain.ServerID) ([]domain.HostKey, error) {
	rows, err := a.q.ListServerHostKeys(ctx, int64(serverID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.HostKey, 0, len(rows))
	for _, h := range rows {
		out = append(out, liteHostKey(h))
	}
	return out, nil
}

func (a *SQLiteQueries) CreateHostKey(ctx context.Context, p CreateHostKeyParams) (domain.HostKey, error) {
	h, err := a.q.CreateServerHostKey(ctx, lite.CreateServerHostKeyParams{
		ServerID: int64(p.ServerID), Algorithm: p.Algorithm, Fingerprint: p.Fingerprint,
		PublicKey: p.PublicKey, State: string(p.State),
		TrustedAt: formatSQLiteTimePtr(p.TrustedAt), TrustedBy: optID(p.TrustedBy),
	})
	return liteHostKey(h), err
}

func (a *SQLiteQueries) UpdateHostKeyState(ctx context.Context, p UpdateHostKeyStateParams) error {
	return a.q.UpdateHostKeyState(ctx, lite.UpdateHostKeyStateParams{
		ID: p.ID, State: string(p.State), TrustedAt: formatSQLiteTimePtr(p.TrustedAt), TrustedBy: optID(p.TrustedBy),
	})
}

func (a *SQLiteQueries) DeleteHostKeys(ctx context.Context, serverID domain.ServerID) error {
	return a.q.DeleteServerHostKeys(ctx, int64(serverID))
}

// --- tags -------------------------------------------------------------------

func (a *SQLiteQueries) UpsertTag(ctx context.Context, name string) (domain.Tag, error) {
	t, err := a.q.UpsertTag(ctx, name)
	if err != nil {
		return domain.Tag{}, err
	}
	return domain.Tag{ID: t.ID, Name: t.Name, CreatedAt: t.CreatedAt}, nil
}

func (a *SQLiteQueries) ListTags(ctx context.Context) ([]domain.Tag, error) {
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

func (a *SQLiteQueries) AddServerTag(ctx context.Context, serverID domain.ServerID, tagID int64) error {
	return a.q.AddServerTag(ctx, lite.AddServerTagParams{ServerID: int64(serverID), TagID: tagID})
}

func (a *SQLiteQueries) ClearServerTags(ctx context.Context, serverID domain.ServerID) error {
	return a.q.ClearServerTags(ctx, int64(serverID))
}

func (a *SQLiteQueries) DeleteOrphanTags(ctx context.Context) (int64, error) {
	return a.q.DeleteOrphanTags(ctx)
}

// --- per-server permissions -------------------------------------------------

func (a *SQLiteQueries) ListServerPermissions(ctx context.Context, userID domain.UserID, serverID domain.ServerID) ([]domain.Permission, error) {
	names, err := a.q.ListServerPermissions(ctx, lite.ListServerPermissionsParams{
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

func (a *SQLiteQueries) GrantServerPermission(ctx context.Context, p GrantServerPermissionParams) error {
	perm, err := a.q.GetPermissionByName(ctx, string(p.Permission))
	if err != nil {
		return err
	}
	return a.q.GrantServerPermission(ctx, lite.GrantServerPermissionParams{
		UserID: int64(p.UserID), ServerID: int64(p.ServerID),
		PermissionID: perm.ID, GrantedBy: optID(p.GrantedBy),
	})
}

func (a *SQLiteQueries) ClearServerPermissions(ctx context.Context, userID domain.UserID, serverID domain.ServerID) error {
	return a.q.ClearServerPermissions(ctx, lite.ClearServerPermissionsParams{
		UserID: int64(userID), ServerID: int64(serverID),
	})
}

func (a *SQLiteQueries) ListAccessibleServerIDs(ctx context.Context, userID domain.UserID) ([]domain.ServerID, error) {
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

func (a *SQLiteQueries) ListServerPermissionGrants(ctx context.Context, userID domain.UserID) ([]ServerGrant, error) {
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

func liteAuditEvent(x lite.AuditLog) domain.AuditEvent {
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

func liteAuditParams(p InsertAuditParams) lite.InsertAuditLogParams {
	return lite.InsertAuditLogParams{
		ActorID: optID(p.ActorID), ActorName: p.ActorName, Action: p.Action, Target: p.Target,
		ServerID: optServerID(p.ServerID), ServerName: p.ServerName, Result: string(p.Result),
		RequestID: p.RequestID, Ip: p.IP, UserAgent: p.UserAgent, Metadata: jsonOr(p.Metadata, "{}"),
	}
}

func (a *SQLiteQueries) InsertAudit(ctx context.Context, p InsertAuditParams) (domain.AuditEvent, error) {
	e, err := a.q.InsertAuditLog(ctx, liteAuditParams(p))
	return liteAuditEvent(e), err
}

// InsertAuditTx writes an audit record inside the caller's transaction, so a
// security-sensitive change and its audit entry commit together (or not at
// all). If the audit write fails, the change fails with it.
func (a *SQLiteQueries) InsertAuditTx(ctx context.Context, tx *sql.Tx, p InsertAuditParams) (domain.AuditEvent, error) {
	q := a.q.WithTx(tx)
	e, err := q.InsertAuditLog(ctx, liteAuditParams(p))
	return liteAuditEvent(e), err
}

func liteAuditQuery(p AuditQueryParams) lite.ListAuditLogsParams {
	return lite.ListAuditLogsParams{
		Limit: p.Limit, Offset: p.Offset,
		ActorID: optID(p.ActorID), ServerID: optServerID(p.ServerID),
		Action: nullString(p.Action), Result: nullString(p.Result), Ip: nullString(p.IP),
		RequestID: nullString(p.RequestID),
		FromTs:    nullTime(p.From), ToTs: nullTime(p.To), Search: nullString(p.Search),
	}
}

func (a *SQLiteQueries) ListAudit(ctx context.Context, p AuditQueryParams) ([]domain.AuditEvent, error) {
	rows, err := a.q.ListAuditLogs(ctx, liteAuditQuery(p))
	if err != nil {
		return nil, err
	}
	out := make([]domain.AuditEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, liteAuditEvent(r))
	}
	return out, nil
}

func (a *SQLiteQueries) CountAudit(ctx context.Context, p AuditQueryParams) (int64, error) {
	return a.q.CountAuditLogs(ctx, lite.CountAuditLogsParams{
		ActorID: optID(p.ActorID), ServerID: optServerID(p.ServerID),
		Action: nullString(p.Action), Result: nullString(p.Result), Ip: nullString(p.IP),
		RequestID: nullString(p.RequestID),
		FromTs:    nullTime(p.From), ToTs: nullTime(p.To), Search: nullString(p.Search),
	})
}

func (a *SQLiteQueries) CountSecurityEvents(ctx context.Context, since time.Time) (int64, error) {
	return a.q.CountSecurityEvents(ctx, since)
}

// DeleteAuditBefore is the single permitted deletion path for audit rows.
// Callers record an AUDIT_PRUNED event so pruning is itself visible.
func (a *SQLiteQueries) DeleteAuditBefore(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteAuditBefore(ctx, before)
}

// --- jobs -------------------------------------------------------------------

func liteJob(j lite.Job) domain.Job {
	out := domain.Job{
		ID:          j.ID,
		Kind:        j.Kind,
		Status:      domain.JobStatus(j.Status),
		Priority:    int(j.Priority),
		Attempts:    int(j.Attempts),
		MaxAttempts: int(j.MaxAttempts),
		RunAt:       j.RunAt,
		LockedBy:    ptrFromNullString(j.LockedBy),
		LockedAt:    parseSQLiteTimePtrStr(j.LockedAt),
		Payload:     j.Payload,
		Progress:    j.Progress,
		LastError:   j.LastError,
		CreatedAt:   j.CreatedAt,
		UpdatedAt:   j.UpdatedAt,
		FinishedAt:  parseSQLiteTimePtrStr(j.FinishedAt),
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

func (a *SQLiteQueries) EnqueueJob(ctx context.Context, p EnqueueJobParams) (domain.Job, error) {
	j, err := a.q.EnqueueJob(ctx, lite.EnqueueJobParams{
		Kind: p.Kind, Priority: int64(p.Priority), MaxAttempts: int64(p.MaxAttempts),
		RunAt: p.RunAt, Payload: jsonOr(p.Payload, "{}"),
		CreatedBy: optID(p.CreatedBy), ServerID: optServerID(p.ServerID), DedupeKey: p.DedupeKey,
	})
	return liteJob(j), err
}

func (a *SQLiteQueries) GetJob(ctx context.Context, id int64) (domain.Job, error) {
	j, err := a.q.GetJob(ctx, id)
	return liteJob(j), err
}

func (a *SQLiteQueries) ListJobs(ctx context.Context, p ListJobsParams) ([]domain.Job, error) {
	rows, err := a.q.ListJobs(ctx, lite.ListJobsParams{
		Limit: p.Limit, Offset: p.Offset,
		Status: nullString(p.Status), Kind: nullString(p.Kind), ServerID: optServerID(p.ServerID), CreatedBy: optID(p.CreatedBy),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Job, 0, len(rows))
	for _, j := range rows {
		out = append(out, liteJob(j))
	}
	return out, nil
}

func (a *SQLiteQueries) CountJobs(ctx context.Context, p ListJobsParams) (int64, error) {
	return a.q.CountJobs(ctx, lite.CountJobsParams{
		Status: nullString(p.Status), Kind: nullString(p.Kind), ServerID: optServerID(p.ServerID), CreatedBy: optID(p.CreatedBy),
	})
}

func (a *SQLiteQueries) CountJobsByStatus(ctx context.Context) (map[string]int64, error) {
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
func (a *SQLiteQueries) ClaimJob(ctx context.Context, workerID string) (domain.Job, error) {
	j, err := a.q.ClaimJob(ctx, &workerID)
	return liteJob(j), err
}

func (a *SQLiteQueries) ClaimJobByKind(ctx context.Context, workerID, kind string) (domain.Job, error) {
	j, err := a.q.ClaimJobByKind(ctx, lite.ClaimJobByKindParams{
		LockedBy: &workerID, Kind: kind,
	})
	return liteJob(j), err
}

func (a *SQLiteQueries) CompleteJob(ctx context.Context, id int64) error {
	return a.q.CompleteJob(ctx, id)
}

func (a *SQLiteQueries) UpdateJobProgress(ctx context.Context, id int64, progress float64) error {
	return a.q.UpdateJobProgress(ctx, lite.UpdateJobProgressParams{ID: id, Progress: progress})
}

func (a *SQLiteQueries) HeartbeatJob(ctx context.Context, id int64) error {
	return a.q.HeartbeatJob(ctx, id)
}

func (a *SQLiteQueries) FailJob(ctx context.Context, id int64, runAt time.Time, errMsg string) error {
	return a.q.FailJob(ctx, lite.FailJobParams{ID: id, RunAt: runAt, LastError: errMsg})
}

func (a *SQLiteQueries) DeadJob(ctx context.Context, id int64, errMsg string) error {
	return a.q.DeadJob(ctx, lite.DeadJobParams{ID: id, LastError: errMsg})
}

func (a *SQLiteQueries) CancelJob(ctx context.Context, id int64) error {
	return a.q.CancelJob(ctx, id)
}

func (a *SQLiteQueries) RequeueJob(ctx context.Context, id int64, runAt time.Time) error {
	return a.q.RequeueJob(ctx, lite.RequeueJobParams{ID: id, RunAt: runAt})
}

func (a *SQLiteQueries) ListStaleJobs(ctx context.Context, olderThan time.Time) ([]domain.Job, error) {
	rows, err := a.q.ListStaleJobs(ctx, formatSQLiteTimePtr(&olderThan))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Job, 0, len(rows))
	for _, j := range rows {
		out = append(out, liteJob(j))
	}
	return out, nil
}

func (a *SQLiteQueries) PromoteRetryingJobs(ctx context.Context) (int64, error) {
	return a.q.PromoteRetryingJobs(ctx)
}

func (a *SQLiteQueries) DeleteFinishedJobsBefore(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteFinishedJobsBefore(ctx, formatSQLiteTimePtr(&before))
}

// --- metrics ----------------------------------------------------------------

func (a *SQLiteQueries) UpsertMetricSample(ctx context.Context, s domain.MetricSample) error {
	return a.q.UpsertMetricSample(ctx, lite.UpsertMetricSampleParams{
		ServerID: int64(s.ServerID), Ts: s.Timestamp,
		CpuPct: s.CPUPct, Load1: s.Load1, Load5: s.Load5, Load15: s.Load15,
		MemTotal: s.MemTotal, MemUsed: s.MemUsed, MemAvailable: s.MemAvailable,
		MemCached: s.MemCached, MemBuffers: s.MemBuffers,
		SwapTotal: s.SwapTotal, SwapUsed: s.SwapUsed,
		NetRxBytes: s.NetRxBytes, NetTxBytes: s.NetTxBytes,
		DiskReadBytes: s.DiskReadBytes, DiskWriteBytes: s.DiskWriteBytes,
		UptimeSeconds: s.UptimeSeconds, ProcessCount: i32ToI64(s.ProcessCount),
	})
}

func liteMetric(m lite.MetricSample) domain.MetricSample {
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
		ProcessCount:   i64ToI32(m.ProcessCount),
	}
}

func (a *SQLiteQueries) GetLatestMetricSample(ctx context.Context, serverID domain.ServerID) (domain.MetricSample, error) {
	m, err := a.q.GetLatestMetricSample(ctx, int64(serverID))
	return liteMetric(m), err
}

func (a *SQLiteQueries) ListMetricSamples(ctx context.Context, p MetricRangeParams) ([]domain.MetricSample, error) {
	rows, err := a.q.ListMetricSamples(ctx, lite.ListMetricSamplesParams{
		ServerID: int64(p.ServerID), Ts: p.From, Ts_2: p.To, Limit: p.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MetricSample, 0, len(rows))
	for _, m := range rows {
		out = append(out, liteMetric(m))
	}
	return out, nil
}

func liteFilesystem(f lite.MetricFilesystem) domain.Filesystem {
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

func (a *SQLiteQueries) UpsertMetricFilesystem(ctx context.Context, f domain.Filesystem) error {
	return a.q.UpsertMetricFilesystem(ctx, lite.UpsertMetricFilesystemParams{
		ServerID: int64(f.ServerID), Ts: f.Timestamp, MountPoint: f.MountPoint,
		Device: f.Device, FsType: f.FSType,
		TotalBytes: f.TotalBytes, UsedBytes: f.UsedBytes, AvailBytes: f.AvailBytes, UsedPct: f.UsedPct,
	})
}

func (a *SQLiteQueries) ListLatestFilesystems(ctx context.Context, serverID domain.ServerID) ([]domain.Filesystem, error) {
	rows, err := a.q.ListLatestFilesystems(ctx, int64(serverID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Filesystem, 0, len(rows))
	for _, f := range rows {
		out = append(out, liteFilesystem(f))
	}
	return out, nil
}

func (a *SQLiteQueries) DeleteMetricSamplesBefore(ctx context.Context, before time.Time) (int64, error) {
	return a.q.DeleteMetricSamplesBefore(ctx, before)
}

// --- misc -------------------------------------------------------------------

func (a *SQLiteQueries) Ping(ctx context.Context) error {
	_, err := a.q.Ping(ctx)
	return err
}

var _ Queries = (*SQLiteQueries)(nil)
