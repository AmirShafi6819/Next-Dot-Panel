package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// sessionTouchInterval throttles last_seen_at writes: one per authenticated
// request would be a write per request against the sessions table.
const sessionTouchInterval = time.Minute

// LoginInput is everything a login attempt records (Design Spec section 11.3).
type LoginInput struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
	RequestID string
}

// RequestMeta carries request context onto audit records.
type RequestMeta struct {
	RequestID string
	IP        string
	UserAgent string
}

// LoginResult is a successful authentication.
type LoginResult struct {
	// Token is the opaque session cookie value. It is shown once and only its
	// SHA-256 is persisted.
	Token string
	// CSRFToken is the double-submit token issued alongside the cookie.
	CSRFToken string
	Session   domain.Session
	User      domain.User
}

// Actor is the authenticated caller attached to a request context.
type Actor struct {
	UserID      domain.UserID
	Username    string
	SessionID   string
	Permissions []domain.Permission
	// ReauthAt is when this session last passed re-authentication, if ever.
	ReauthAt *time.Time
}

// IsReauthenticated reports whether the session re-authenticated within the
// configured window. Enforcement is wired in the re-auth middleware.
func (a Actor) IsReauthenticated(window time.Duration, now time.Time) bool {
	if a.ReauthAt == nil {
		return false
	}
	return now.Sub(*a.ReauthAt) <= window
}

// Profile is the payload for the current-user endpoint.
type Profile struct {
	User domain.User
	// DefaultCredentialsWarning is true while this account still carries the
	// bootstrap default password (Design Spec section 36.9).
	DefaultCredentialsWarning bool
}

// Options configures the auth service.
type Options struct {
	SessionLifetime   time.Duration
	SessionIdle       time.Duration
	ReauthWindow      time.Duration
	BootstrapEnabled  bool
	BootstrapUsername string
	BootstrapPassword string
}

// Service implements login, session authentication, logout, password change,
// re-authentication and session management.
type Service struct {
	q    repos.Queries
	opts Options
	log  logger
	now  func() time.Time
}

type logger interface {
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

type discardLogger struct{}

func (discardLogger) Info(context.Context, string, ...any)  {}
func (discardLogger) Warn(context.Context, string, ...any)  {}
func (discardLogger) Error(context.Context, string, ...any) {}

// New builds an auth service.
func New(q repos.Queries, opts Options, log logger) *Service {
	if log == nil {
		log = discardLogger{}
	}
	if opts.SessionLifetime <= 0 {
		opts.SessionLifetime = 12 * time.Hour
	}
	if opts.SessionIdle <= 0 {
		opts.SessionIdle = 30 * time.Minute
	}
	if opts.ReauthWindow <= 0 {
		opts.ReauthWindow = 15 * time.Minute
	}
	return &Service{q: q, opts: opts, log: log, now: time.Now}
}

// SetClock replaces the time source. Tests use it; production does not.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Options exposes the effective configuration (for the /me endpoint).
func (s *Service) Options() Options { return s.opts }

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

// Bootstrap seeds the first administrator when the users table is empty and
// otherwise detects accounts still holding default credentials. It runs after
// migrations on every start (Design Spec section 368).
func (s *Service) Bootstrap(ctx context.Context) error {
	count, err := s.q.CountAllUsers(ctx)
	if err != nil {
		return fmt.Errorf("auth: count users: %w", err)
	}
	if count == 0 {
		return s.seedBootstrapAdmin(ctx)
	}
	pending, err := s.q.CountUsersWithDefaultCredentials(ctx)
	if err != nil {
		return fmt.Errorf("auth: count default credentials: %w", err)
	}
	if pending > 0 {
		s.writeAudit(ctx, auditEvent{
			action:   domain.ActionSecurityEvent,
			target:   "users",
			result:   domain.ResultSuccess,
			metadata: map[string]any{"reason": "default_credentials_present", "count": pending},
		})
		s.log.Warn(ctx, "an account still uses bootstrap default credentials; change the password",
			"accounts", pending)
	}
	return nil
}

func (s *Service) seedBootstrapAdmin(ctx context.Context) error {
	if !s.opts.BootstrapEnabled {
		s.log.Warn(ctx, "no users exist and bootstrap seeding is disabled; create an administrator with the CLI first")
		return nil
	}
	hash, err := Hash(s.opts.BootstrapPassword)
	if err != nil {
		return fmt.Errorf("auth: hash bootstrap password: %w", err)
	}
	user, err := s.q.CreateUser(ctx, repos.CreateUserParams{
		Username:           s.opts.BootstrapUsername,
		PasswordHash:       hash,
		DisplayName:        "Administrator",
		IsActive:           true,
		IsBootstrapDefault: true,
		MustChangePassword: true,
	})
	if err != nil {
		return fmt.Errorf("auth: create bootstrap administrator: %w", err)
	}
	s.writeAudit(ctx, auditEvent{
		actorID:   &user.ID,
		actorName: user.Username,
		action:    domain.ActionSecurityEvent,
		target:    "user:" + user.Username,
		result:    domain.ResultSuccess,
		metadata:  map[string]any{"reason": "bootstrap_admin_created"},
	})
	s.log.Warn(ctx, "bootstrap administrator created with default credentials; change the password immediately",
		"username", user.Username)
	return nil
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

// Login authenticates a username and password and, on success, creates a
// session. Every failure path returns ErrInvalidCredentials so the response
// never distinguishes "no such user" from "wrong password" from "disabled".
func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	now := s.now()
	user, err := s.q.GetUserByUsername(ctx, in.Username)
	if errors.Is(err, sql.ErrNoRows) {
		// Spend the same time as a real verification so user existence cannot
		// be timed.
		dummyVerify(in.Password)
		s.recordFailure(ctx, nil, in, domain.FailureUnknownUser)
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: load user: %w", err)
	}

	verified, verr := Verify(in.Password, user.PasswordHash)
	if verr != nil {
		s.log.Error(ctx, "stored password hash is unusable", "user_id", user.ID, "error", verr)
		dummyVerify(in.Password)
		s.recordFailure(ctx, &user.ID, in, domain.FailureBadPassword)
		return LoginResult{}, ErrInvalidCredentials
	}
	if !verified.Valid {
		s.recordFailure(ctx, &user.ID, in, domain.FailureBadPassword)
		return LoginResult{}, ErrInvalidCredentials
	}
	if !user.CanSignIn() {
		s.recordFailure(ctx, &user.ID, in, domain.FailureAccountDisabled)
		return LoginResult{}, ErrInvalidCredentials
	}

	// The password matched: upgrade a hash stored under weaker parameters
	// without clearing the bootstrap-default flag (that happens only on an
	// actual password change).
	if verified.NeedsRehash {
		if hash, herr := Hash(in.Password); herr == nil {
			if uerr := s.q.UpdateUserPasswordHash(ctx, user.ID, hash); uerr != nil {
				s.log.Warn(ctx, "password hash upgrade failed", "user_id", user.ID, "error", uerr)
			}
		}
	}

	token, tokenHash, err := newSessionToken()
	if err != nil {
		return LoginResult{}, err
	}
	sessionID, err := newSessionID()
	if err != nil {
		return LoginResult{}, err
	}
	csrf, err := newCSRFToken()
	if err != nil {
		return LoginResult{}, err
	}
	session, err := s.q.CreateSession(ctx, repos.CreateSessionParams{
		ID:        sessionID,
		UserID:    user.ID,
		TokenHash: tokenHash,
		IP:        in.IP,
		UserAgent: in.UserAgent,
		ExpiresAt: now.Add(s.opts.SessionLifetime),
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: create session: %w", err)
	}
	if err := s.q.RecordUserLogin(ctx, user.ID); err != nil {
		s.log.Warn(ctx, "recording last login failed", "user_id", user.ID, "error", err)
	}
	s.recordAttempt(ctx, &user.ID, in.Username, in.IP, in.UserAgent, true, "", session.ID)
	s.writeAudit(ctx, auditEvent{
		actorID:   &user.ID,
		actorName: user.Username,
		action:    domain.ActionLoginSuccess,
		target:    "session:" + session.ID,
		result:    domain.ResultSuccess,
		meta:      RequestMeta{RequestID: in.RequestID, IP: in.IP, UserAgent: in.UserAgent},
	})
	return LoginResult{Token: token, CSRFToken: csrf, Session: session, User: user}, nil
}

// Logout revokes the actor's session and audits the event.
func (s *Service) Logout(ctx context.Context, actor Actor, meta RequestMeta) error {
	if err := s.q.RevokeSession(ctx, actor.SessionID); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	s.writeAudit(ctx, auditEvent{
		actorID:   &actor.UserID,
		actorName: actor.Username,
		action:    domain.ActionLogout,
		target:    "session:" + actor.SessionID,
		result:    domain.ResultSuccess,
		meta:      meta,
	})
	return nil
}

// ---------------------------------------------------------------------------
// Session authentication
// ---------------------------------------------------------------------------

// Authenticate resolves a session token into an Actor, enforcing absolute and
// idle expiry, account status and touch throttling.
func (s *Service) Authenticate(ctx context.Context, token string) (Actor, error) {
	if token == "" {
		return Actor{}, ErrUnauthenticated
	}
	now := s.now()
	session, err := s.q.GetSessionByTokenHash(ctx, hashSessionToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return Actor{}, ErrUnauthenticated
	}
	if err != nil {
		return Actor{}, fmt.Errorf("auth: load session: %w", err)
	}
	if !session.Active(now) {
		return Actor{}, ErrUnauthenticated
	}
	if now.Sub(session.LastSeenAt) > s.opts.SessionIdle {
		// Idle expiry is a transition but not an audited event (spec: expiry by
		// time is exempt).
		if rerr := s.q.RevokeSession(ctx, session.ID); rerr != nil {
			s.log.Warn(ctx, "revoking idle session failed", "session_id", session.ID, "error", rerr)
		}
		return Actor{}, ErrUnauthenticated
	}

	user, err := s.q.GetUserByID(ctx, session.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return Actor{}, ErrUnauthenticated
	}
	if err != nil {
		return Actor{}, fmt.Errorf("auth: load session user: %w", err)
	}
	if !user.CanSignIn() {
		if rerr := s.q.RevokeSession(ctx, session.ID); rerr != nil {
			s.log.Warn(ctx, "revoking disabled user session failed", "session_id", session.ID, "error", rerr)
		}
		return Actor{}, ErrUnauthenticated
	}

	if now.Sub(session.LastSeenAt) >= sessionTouchInterval {
		if terr := s.q.TouchSession(ctx, session.ID); terr != nil {
			s.log.Warn(ctx, "touching session failed", "session_id", session.ID, "error", terr)
		}
	}
	perms, err := s.q.ListUserPermissions(ctx, user.ID)
	if err != nil {
		// RBAC is additive: an unauthorised-but-authenticated caller must not
		// become an error. Fail closed on permissions instead.
		s.log.Error(ctx, "loading permissions failed", "user_id", user.ID, "error", err)
		perms = nil
	}
	return Actor{
		UserID:      user.ID,
		Username:    user.Username,
		SessionID:   session.ID,
		Permissions: perms,
		ReauthAt:    session.ReauthAt,
	}, nil
}

// ---------------------------------------------------------------------------
// Password change and re-authentication
// ---------------------------------------------------------------------------

// ChangePassword requires the current password (re-authentication by proof),
// applies the new one, revokes every other session and audits the change.
func (s *Service) ChangePassword(ctx context.Context, actor Actor, current, next string, meta RequestMeta) error {
	user, err := s.q.GetUserByID(ctx, actor.UserID)
	if err != nil {
		return fmt.Errorf("auth: load user: %w", err)
	}
	verified, verr := Verify(current, user.PasswordHash)
	if verr != nil {
		s.log.Error(ctx, "stored password hash is unusable", "user_id", user.ID, "error", verr)
		s.writeAudit(ctx, s.actorAudit(actor, domain.ActionPasswordChanged, domain.ResultFailure, meta,
			map[string]any{"reason": "hash_unusable"}))
		return ErrInvalidCredentials
	}
	if !verified.Valid {
		s.writeAudit(ctx, s.actorAudit(actor, domain.ActionPasswordChanged, domain.ResultFailure, meta,
			map[string]any{"reason": "wrong_current_password"}))
		return ErrInvalidCredentials
	}
	if err := ValidatePassword(next); err != nil {
		return err
	}
	if next == current {
		return ErrPasswordUnchanged
	}
	hash, err := Hash(next)
	if err != nil {
		return fmt.Errorf("auth: hash new password: %w", err)
	}
	if _, err := s.q.SetUserPassword(ctx, repos.SetUserPasswordParams{
		ID:           user.ID,
		PasswordHash: hash,
		MustChange:   false,
	}); err != nil {
		return fmt.Errorf("auth: store new password: %w", err)
	}
	if _, err := s.q.RevokeUserSessionsExcept(ctx, user.ID, actor.SessionID); err != nil {
		s.log.Warn(ctx, "revoking other sessions failed", "user_id", user.ID, "error", err)
	}
	s.writeAudit(ctx, s.actorAudit(actor, domain.ActionPasswordChanged, domain.ResultSuccess, meta, nil))
	return nil
}

// Reauthenticate proves possession of the password again and refreshes the
// session's re-auth timestamp for sensitive operations.
func (s *Service) Reauthenticate(ctx context.Context, actor Actor, password string, meta RequestMeta) (time.Time, error) {
	user, err := s.q.GetUserByID(ctx, actor.UserID)
	if err != nil {
		return time.Time{}, fmt.Errorf("auth: load user: %w", err)
	}
	verified, verr := Verify(password, user.PasswordHash)
	if verr != nil {
		s.log.Error(ctx, "stored password hash is unusable", "user_id", user.ID, "error", verr)
		s.writeAudit(ctx, s.actorAudit(actor, domain.ActionReauthFailed, domain.ResultFailure, meta, nil))
		return time.Time{}, ErrInvalidCredentials
	}
	if !verified.Valid {
		s.writeAudit(ctx, s.actorAudit(actor, domain.ActionReauthFailed, domain.ResultFailure, meta, nil))
		return time.Time{}, ErrInvalidCredentials
	}
	if err := s.q.SetSessionReauthAt(ctx, actor.SessionID); err != nil {
		return time.Time{}, fmt.Errorf("auth: record re-auth: %w", err)
	}
	now := s.now()
	s.writeAudit(ctx, s.actorAudit(actor, domain.ActionReauthSuccess, domain.ResultSuccess, meta, nil))
	return now, nil
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

// ListSessions returns the actor's own sessions.
func (s *Service) ListSessions(ctx context.Context, actor Actor) ([]domain.Session, error) {
	sessions, err := s.q.ListUserSessions(ctx, actor.UserID)
	if err != nil {
		return nil, fmt.Errorf("auth: list sessions: %w", err)
	}
	return sessions, nil
}

// RevokeSession revokes one of the actor's own sessions. A session owned by
// anyone else returns ErrNotFound, indistinguishable from a session that does
// not exist (IDOR).
func (s *Service) RevokeSession(ctx context.Context, actor Actor, sessionID string, meta RequestMeta) error {
	session, err := s.q.GetSessionByID(ctx, sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("auth: load session: %w", err)
	}
	if session.UserID != actor.UserID {
		s.writeAudit(ctx, s.actorAudit(actor, domain.ActionSessionRevoked, domain.ResultDenied, meta,
			map[string]any{"session_id": sessionID}))
		return ErrNotFound
	}
	if err := s.q.RevokeSession(ctx, sessionID); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	s.writeAudit(ctx, s.actorAudit(actor, domain.ActionSessionRevoked, domain.ResultSuccess, meta,
		map[string]any{"session_id": sessionID}))
	return nil
}

// Profile returns the actor's account plus the default-credential warning.
func (s *Service) Profile(ctx context.Context, actor Actor) (Profile, error) {
	user, err := s.q.GetUserByID(ctx, actor.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("auth: load user: %w", err)
	}
	warn := false
	if user.IsBootstrapDefault {
		// Only warn while the stored hash still matches the bootstrap password
		// itself; the flag alone can go stale after a CLI password reset.
		warn = s.matchesBootstrapPassword(user)
	}
	return Profile{User: user, DefaultCredentialsWarning: warn}, nil
}

func (s *Service) matchesBootstrapPassword(user domain.User) bool {
	if s.opts.BootstrapPassword == "" {
		return false
	}
	verified, err := Verify(s.opts.BootstrapPassword, user.PasswordHash)
	return err == nil && verified.Valid
}

// ---------------------------------------------------------------------------
// Audit and login-history plumbing
// ---------------------------------------------------------------------------

type auditEvent struct {
	actorID   *domain.UserID
	actorName string
	action    string
	target    string
	result    domain.AuditResult
	meta      RequestMeta
	metadata  map[string]any
}

func (s *Service) actorAudit(actor Actor, action string, result domain.AuditResult, meta RequestMeta, metadata map[string]any) auditEvent {
	return auditEvent{
		actorID:   &actor.UserID,
		actorName: actor.Username,
		action:    action,
		target:    "session:" + actor.SessionID,
		result:    result,
		meta:      meta,
		metadata:  metadata,
	}
}

// writeAudit is best-effort: an audit failure must never turn a successful
// login into a 500, but it is logged loudly.
func (s *Service) writeAudit(ctx context.Context, ev auditEvent) {
	var metadata []byte
	if ev.metadata != nil {
		var err error
		metadata, err = json.Marshal(ev.metadata)
		if err != nil {
			s.log.Warn(ctx, "sanitising audit metadata failed", "action", ev.action, "error", err)
			metadata = nil
		}
	}
	_, err := s.q.InsertAudit(ctx, repos.InsertAuditParams{
		ActorID:   ev.actorID,
		ActorName: ev.actorName,
		Action:    ev.action,
		Target:    ev.target,
		Result:    ev.result,
		RequestID: ev.meta.RequestID,
		IP:        ev.meta.IP,
		UserAgent: ev.meta.UserAgent,
		Metadata:  metadata,
	})
	if err != nil {
		s.log.Error(ctx, "writing audit record failed", "action", ev.action, "error", err)
	}
}

func (s *Service) recordFailure(ctx context.Context, userID *domain.UserID, in LoginInput, reason string) {
	s.recordAttempt(ctx, userID, in.Username, in.IP, in.UserAgent, false, reason, "")
	s.writeAudit(ctx, auditEvent{
		actorID:   userID,
		actorName: in.Username,
		action:    domain.ActionLoginFailed,
		target:    "user:" + in.Username,
		result:    domain.ResultFailure,
		meta:      RequestMeta{RequestID: in.RequestID, IP: in.IP, UserAgent: in.UserAgent},
		metadata:  map[string]any{"reason": reason},
	})
}

func (s *Service) recordAttempt(ctx context.Context, userID *domain.UserID, username, ip, ua string, success bool, reason, sessionID string) {
	if _, err := s.q.InsertLoginAttempt(ctx, repos.InsertLoginAttemptParams{
		UserID:        userID,
		Username:      username,
		IP:            ip,
		UserAgent:     ua,
		Success:       success,
		FailureReason: reason,
		SessionID:     sessionID,
	}); err != nil {
		s.log.Warn(ctx, "recording login attempt failed", "username", username, "error", err)
	}
}

// dummyVerify runs a full Argon2id verification against a throwaway hash so a
// missing user costs the same time as a wrong password.
func dummyVerify(password string) {
	dummyOnce.Do(func() {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err == nil {
			if hash, herr := Hash(string(buf)); herr == nil {
				dummyHash = hash
			}
		}
		if dummyHash == "" {
			dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}
	})
	//nolint:errcheck // outcome deliberately discarded
	_, _ = Verify(password, dummyHash)
}

var (
	dummyOnce sync.Once
	dummyHash string
)
