package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi/middleware"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/terminal"
)

// Terminal bridges an authenticated WebSocket to a PTY session.
//
// Wire protocol (documented in docs/terminal.md):
//   - server → client: binary frames are raw PTY output.
//   - server → client: text JSON {"type":"ready","session_id":...} and
//     {"type":"exit","code":N}.
//   - client → server: text JSON {"type":"input","data":"..."} or
//     {"type":"resize","cols":C,"rows":R} or {"type":"close"}.
//   - client → server: binary frames are treated as raw input.
type Terminal struct {
	Manager        *terminal.Manager
	Log            *logging.Logger
	OriginPatterns []string
}

type terminalMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// ServeHTTP implements GET /api/v1/servers/{id}/terminal.
func (h *Terminal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor, ok := middleware.ActorFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, ok := serverIDParam(w, r)
	if !ok {
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: h.OriginPatterns})
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(1 << 20)

	sess, err := h.Manager.Open(r.Context(), actor, id, terminal.OpenOptions{
		Term:      r.URL.Query().Get("term"),
		Cols:      uint16(atoiDefault(r.URL.Query().Get("cols"), 80)),
		Rows:      uint16(atoiDefault(r.URL.Query().Get("rows"), 24)),
		RequestID: logging.RequestID(r.Context()),
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		_ = c.Write(r.Context(), websocket.MessageText, mustJSON(terminalMessage{Type: "error", Data: terminalError(err)}))
		_ = c.Close(websocket.StatusPolicyViolation, "cannot open terminal")
		return
	}
	defer h.Manager.Close(sess.ID, "client_disconnected")

	if err := writeWSJSON(r.Context(), c, terminalMessage{Type: "ready", Data: sess.ID}); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// PTY output → WebSocket. The exit message uses a detached context because
	// the request context is cancelled when the shell exits.
	// #nosec G118 -- detached by design; request context is dead at shell exit.
	go func() {
		defer cancel()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := sess.Read(buf)
			if n > 0 {
				if werr := c.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				code, _ := sess.Wait()
				_ = writeWSJSON(context.Background(), c, terminalMessage{Type: "exit", Data: strconv.Itoa(code)})
				_ = c.Close(websocket.StatusNormalClosure, "shell exited")
				return
			}
		}
	}()

	// WebSocket → PTY input.
	for {
		typ, data, rerr := c.Read(ctx)
		if rerr != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			if _, werr := sess.Write(data); werr != nil {
				return
			}
		case websocket.MessageText:
			var msg terminalMessage
			if jerr := json.Unmarshal(data, &msg); jerr != nil {
				continue
			}
			switch msg.Type {
			case "input":
				if _, werr := sess.Write([]byte(msg.Data)); werr != nil {
					return
				}
			case "resize":
				_ = sess.Resize(ctx, msg.Cols, msg.Rows)
			case "close":
				return
			}
		}
	}
}

func writeWSJSON(ctx context.Context, c *websocket.Conn, v any) error {
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.Write(wctx, websocket.MessageText, mustJSON(v))
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func terminalError(err error) string {
	switch {
	case errors.Is(err, terminal.ErrLimit):
		return "session_limit_reached"
	case errors.Is(err, terminal.ErrForbidden):
		return "forbidden"
	default:
		return "cannot_open_terminal"
	}
}
