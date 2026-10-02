// Package audit writes and reads the append-only audit trail.
//
// Writing is deliberately best-effort: a failure to record an event must never
// turn a successful operation into an error, but it is logged loudly so the gap
// is visible. Services call this instead of reaching into the repository
// directly, which keeps the action vocabulary and metadata sanitising in one
// place (Design Spec §27).
package audit

import (
	"context"
	"encoding/json"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Writer records audit events.
type Writer struct {
	q   repos.Queries
	log logger
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

// New builds a writer over the given query surface.
func New(q repos.Queries, log logger) *Writer {
	return &Writer{q: q, log: log}
}

// Event is one audit entry. Metadata is a JSON-safe map; it must never contain
// credential material (callers are responsible for that, and the auth package
// already enforces it on its own paths).
type Event struct {
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
	Metadata   map[string]any
}

// Record writes the event. It never returns an error to the caller: audit is a
// side channel, not part of the operation's contract.
func (w *Writer) Record(ctx context.Context, e Event) {
	if w == nil || w.q == nil {
		return
	}
	var metadata []byte
	if e.Metadata != nil {
		var err error
		metadata, err = json.Marshal(e.Metadata)
		if err != nil {
			w.logf("Warn", ctx, "audit metadata could not be encoded", "action", e.Action, "error", err)
			metadata = nil
		}
	}
	if _, err := w.q.InsertAudit(ctx, repos.InsertAuditParams{
		ActorID:    e.ActorID,
		ActorName:  e.ActorName,
		Action:     e.Action,
		Target:     e.Target,
		ServerID:   e.ServerID,
		ServerName: e.ServerName,
		Result:     e.Result,
		RequestID:  e.RequestID,
		IP:         e.IP,
		UserAgent:  e.UserAgent,
		Metadata:   metadata,
	}); err != nil {
		w.logf("Error", ctx, "writing audit record failed", "action", e.Action, "error", err)
	}
}

// Denied records a DENIED outcome, the shape every authorization failure uses.
func (w *Writer) Denied(ctx context.Context, e Event) {
	e.Result = domain.ResultDenied
	w.Record(ctx, e)
}

func (w *Writer) logf(level string, ctx context.Context, msg string, args ...any) {
	if w == nil || w.log == nil {
		return
	}
	if level == "Warn" {
		w.log.Warn(ctx, msg, args...)
		return
	}
	w.log.Error(ctx, msg, args...)
}
