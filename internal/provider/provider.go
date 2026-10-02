// Package provider defines the execution-provider abstraction: the primitives
// every backend (SSH, local) implements, the registry that resolves a target to
// a provider, and the safe error taxonomy.
//
// Providers expose primitives only (Design Spec §8.2). Upload, extract, metrics
// and similar are composed at the service layer from these primitives, so the
// logic exists once and is authorized once.
package provider

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/secret"
)

// ConnectionStatus is a provider's connection lifecycle state.
type ConnectionStatus string

const (
	StatusDisconnected ConnectionStatus = "DISCONNECTED"
	StatusConnecting   ConnectionStatus = "CONNECTING"
	StatusConnected    ConnectionStatus = "CONNECTED"
	StatusReconnecting ConnectionStatus = "RECONNECTING"
	StatusDrained      ConnectionStatus = "DRAINED"
	StatusFailed       ConnectionStatus = "FAILED"
)

// Defaults for command execution.
const (
	DefaultCommandTimeout = 30 * time.Second
	DefaultMaxOutputBytes = 1 << 20 // 1 MiB
)

// TruncatedMarker is appended to output that hit the cap, so a caller can tell
// truncation from a short result.
const TruncatedMarker = "\n[next.panel: output truncated]\n"

// Command is a single command to execute. Path and Args are passed as a slice
// and never concatenated into a shell string (Design Spec §9.3).
type Command struct {
	Path           string
	Args           []string
	Env            []string
	Stdin          io.Reader
	Timeout        time.Duration
	MaxOutputBytes int64
}

// EffectiveTimeout returns the command timeout or the default.
func (c Command) EffectiveTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultCommandTimeout
}

// EffectiveMaxOutput returns the output cap or the default.
func (c Command) EffectiveMaxOutput() int64 {
	if c.MaxOutputBytes > 0 {
		return c.MaxOutputBytes
	}
	return DefaultMaxOutputBytes
}

// ExecResult is the outcome of a command. A non-zero exit code is a result,
// not an error: callers decide what it means (Design Spec §9.3).
type ExecResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Duration  time.Duration
	Truncated bool
}

// CredentialSource yields plaintext credential material lazily. It is
// implemented by credentials.Unwrapped; the interface keeps this package from
// depending on the credentials package. Close must be called when done.
type CredentialSource interface {
	Password() secret.Secret
	PrivateKey() secret.Secret
	Passphrase() secret.Secret
	Close()
}

// PTYOptions configures an interactive terminal.
type PTYOptions struct {
	Term string
	Cols uint16
	Rows uint16
	Env  []string
}

// PTY is an interactive pseudo-terminal. Read receives the remote output
// (including ANSI sequences); Write sends keystrokes.
type PTY interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resize(ctx context.Context, cols, rows uint16) error
	Wait() (exitCode int, err error)
	Close() error
}

// ServerExecutionProvider is the primitive surface every backend implements.
// Policy (upload, extract, metrics, service management) is composed above it
// so it exists once and is authorized once (Design Spec §8.2).
type ServerExecutionProvider interface {
	// ID identifies the provider implementation ("ssh", "local").
	ID() string

	// Connect establishes the connection for the target. It is idempotent for
	// an already-connected provider with the same target.
	Connect(ctx context.Context, t domain.Target, creds CredentialSource) error

	// Disconnect closes the connection.
	Disconnect(ctx context.Context) error

	// Status reports the current lifecycle state.
	Status() ConnectionStatus

	// Ping measures round-trip latency to the target.
	Ping(ctx context.Context) (time.Duration, error)

	// Exec runs a command to completion and captures stdout, stderr and exit
	// status.
	Exec(ctx context.Context, cmd Command) (*ExecResult, error)

	// ExecStream runs a command and returns its combined output as a stream.
	ExecStream(ctx context.Context, cmd Command) (io.ReadCloser, error)

	// OpenPTY opens an interactive terminal session.
	OpenPTY(ctx context.Context, o PTYOptions) (PTY, error)

	// Stat returns metadata for one path.
	Stat(ctx context.Context, path string) (*domain.FileInfo, error)

	// ListDir lists one directory.
	ListDir(ctx context.Context, path string) ([]domain.FileInfo, error)

	// OpenRead opens a file for reading starting at offset.
	OpenRead(ctx context.Context, path string, offset int64) (io.ReadCloser, error)

	// OpenWrite opens a file for writing, truncating it. size is a hint.
	OpenWrite(ctx context.Context, path string, mode os.FileMode, size int64) (io.WriteCloser, error)

	// Remove deletes files, or directories when recursive is set.
	Remove(ctx context.Context, paths []string, recursive bool) error

	// Rename moves a file or directory.
	Rename(ctx context.Context, from, to string) error

	// Mkdir creates a directory and any missing parents.
	Mkdir(ctx context.Context, path string, mode os.FileMode) error
}
