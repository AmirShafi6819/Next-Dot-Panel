// Package dto holds the request/response models of the HTTP API. Generated
// store types never appear here (Design Spec §5): the wire format is its own
// contract and must not move just because the schema did.
package dto

import (
	"encoding/json"
	"net/http"

	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
)

// ErrorBody is the single error envelope. Every error response uses it,
// without exception (Design Spec §25.4).
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail is the content of an error envelope.
type ErrorDetail struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id"`
	Details   map[string]any `json:"details,omitempty"`
}

// NewError builds an error envelope for the given request.
func NewError(r *http.Request, code, message string, details map[string]any) ErrorBody {
	return ErrorBody{Error: ErrorDetail{
		Code:      code,
		Message:   message,
		RequestID: logging.RequestID(r.Context()),
		Details:   details,
	}}
}

// WriteError writes an error response in the standard envelope.
//
// The message is a human-readable projection: no stack traces, no SQL, no
// filesystem paths, no credentials, in any environment (Design Spec §25.4).
// Internal detail belongs in the log, correlated by request_id.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string, details map[string]any) {
	writeJSON(w, status, NewError(r, code, message, details))
}

// WriteJSON writes v as the response body with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	writeJSON(w, status, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// The only values that reach here are the envelope and plain structs;
		// if one cannot be encoded the response is an empty 500 rather than a
		// half-written body.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"internal_error","message":"An internal error occurred."}}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
