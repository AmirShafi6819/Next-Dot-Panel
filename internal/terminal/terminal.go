// Package terminal manages interactive PTY sessions. Each session is bound to
// one authenticated user and one server; opening requires the terminal.open
// permission on that server, and every open/close is audited (Design Spec §16,
// §17, §261). Command contents are never recorded.
package terminal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// Sentinel errors.
var (
	ErrLimit     = errors.New("terminal: session limit reached")
	ErrForbidden = errors.New("terminal: forbidden")
	ErrClosed    = errors.New("terminal: session is closed")
)

// Gateway is the connection gateway (satisfied by *server.Service).
type Gateway interface {
	Connect(ctx context.Context, actor auth.Actor, id domain.ServerID, perm domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error)
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
}

// Limits bounds concurrent terminals.
type Limits struct {
	PerUser     int
	PerServer   int
	Global      int
	IdleTimeout time.Duration
}

// Manager owns the live terminal sessions.
type Manager struct {
	gw     Gateway
	audit  *audit.Writer
	log    logger
	limits Limits

	mu       sync.Mutex
	sessions map[string]*Session
}

// New builds a terminal manager.
func New(gw Gateway, auditWriter *audit.Writer, log logger, limits Limits) *Manager {
	if limits.IdleTimeout <= 0 {
		limits.IdleTimeout = 15 * time.Minute
	}
	return &Manager{gw: gw, audit: auditWriter, log: log, limits: limits, sessions: map[string]*Session{}}
}

// OpenOptions configures a new session.
type OpenOptions struct {
	Term      string
	Cols      uint16
	Rows      uint16
	RequestID string
	IP        string
	UserAgent string
}

// Session is one interactive terminal.
type Session struct {
	ID       string
	UserID   domain.UserID
	ServerID domain.ServerID

	pty provider.PTY
	src provider.CredentialSource

	mu         sync.Mutex
	lastActive time.Time
	closed     bool

	createdAt time.Time
}

// Open authorizes and starts a terminal session.
func (m *Manager) Open(ctx context.Context, actor auth.Actor, serverID domain.ServerID, o OpenOptions) (*Session, error) {
	m.mu.Lock()
	if err := m.checkLimitsLocked(actor.UserID, serverID); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.mu.Unlock()

	p, src, err := m.gw.Connect(ctx, actor, serverID, domain.PermTerminalOpen)
	if err != nil {
		return nil, err
	}
	pty, err := p.OpenPTY(ctx, provider.PTYOptions{Term: o.Term, Cols: o.Cols, Rows: o.Rows})
	if err != nil {
		if src != nil {
			src.Close()
		}
		return nil, err
	}

	id, err := newSessionID()
	if err != nil {
		_ = pty.Close()
		if src != nil {
			src.Close()
		}
		return nil, err
	}
	s := &Session{
		ID: id, UserID: actor.UserID, ServerID: serverID,
		pty: pty, src: src, lastActive: time.Now(), createdAt: time.Now(),
	}

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()

	if m.audit != nil {
		sid := serverID
		m.audit.Record(ctx, audit.Event{
			ActorID: &actor.UserID, ActorName: actor.Username,
			Action: domain.ActionTerminalOpened, Target: "terminal:" + id,
			ServerID: &sid, Result: domain.ResultSuccess,
			RequestID: o.RequestID, IP: o.IP, UserAgent: o.UserAgent,
			Metadata: map[string]any{"cols": o.Cols, "rows": o.Rows},
		})
	}
	return s, nil
}

func (m *Manager) checkLimitsLocked(userID domain.UserID, serverID domain.ServerID) error {
	if m.limits.Global > 0 && len(m.sessions) >= m.limits.Global {
		return ErrLimit
	}
	var perUser, perServer int
	for _, s := range m.sessions {
		if s.UserID == userID {
			perUser++
		}
		if s.ServerID == serverID {
			perServer++
		}
	}
	if m.limits.PerUser > 0 && perUser >= m.limits.PerUser {
		return ErrLimit
	}
	if m.limits.PerServer > 0 && perServer >= m.limits.PerServer {
		return ErrLimit
	}
	return nil
}

// Close terminates a session, closing the PTY and credential source and
// auditing the event. It is idempotent.
func (m *Manager) Close(sessionID, reason string) {
	m.mu.Lock()
	s, ok := m.sessions[sessionID]
	if ok {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	s.close(reason)
	if m.audit != nil {
		sid := s.ServerID
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.audit.Record(ctx, audit.Event{
			ActorID: &s.UserID, Action: domain.ActionTerminalClosed,
			Target: "terminal:" + sessionID, ServerID: &sid,
			Result: domain.ResultSuccess, Metadata: map[string]any{"reason": reason},
		})
	}
}

// CloseAll closes every session (used on shutdown).
func (m *Manager) CloseAll(reason string) {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Close(id, reason)
	}
}

// CloseForServer closes every session on a server (server update/delete).
func (m *Manager) CloseForServer(serverID domain.ServerID, reason string) {
	m.mu.Lock()
	ids := make([]string, 0)
	for id, s := range m.sessions {
		if s.ServerID == serverID {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Close(id, reason)
	}
}

// CloseForUser closes every session belonging to a user (revocation/logout).
func (m *Manager) CloseForUser(userID domain.UserID, reason string) {
	m.mu.Lock()
	ids := make([]string, 0)
	for id, s := range m.sessions {
		if s.UserID == userID {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Close(id, reason)
	}
}

// Sweep closes sessions idle beyond the configured timeout.
func (m *Manager) Sweep(now time.Time) int {
	if m.limits.IdleTimeout <= 0 {
		return 0
	}
	m.mu.Lock()
	ids := make([]string, 0)
	for id, s := range m.sessions {
		if now.Sub(s.LastActive()) > m.limits.IdleTimeout {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Close(id, "idle_timeout")
	}
	return len(ids)
}

// Count reports the number of live sessions.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Session accessors and I/O.

// Read reads remote output.
func (s *Session) Read(p []byte) (int, error) {
	n, err := s.pty.Read(p)
	if n > 0 {
		s.Touch()
	}
	return n, err
}

// Write sends input to the remote shell.
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	s.lastActive = time.Now()
	s.mu.Unlock()
	return s.pty.Write(p)
}

// Resize changes the PTY window size.
func (s *Session) Resize(ctx context.Context, cols, rows uint16) error {
	return s.pty.Resize(ctx, cols, rows)
}

// Wait blocks until the remote shell exits.
func (s *Session) Wait() (int, error) { return s.pty.Wait() }

// Touch marks activity.
func (s *Session) Touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

// LastActive returns the last activity time.
func (s *Session) LastActive() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActive
}

// CreatedAt returns the session start time.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

func (s *Session) close(reason string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.pty.Close()
	if s.src != nil {
		s.src.Close()
	}
	_ = reason
}

func newSessionID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("terminal: generate session id: %w", err)
	}
	return "term_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
