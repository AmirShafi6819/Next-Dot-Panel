// Package sshprovider implements the SSH execution provider. Host-key
// verification fails closed (Design Spec §9.1): an unknown key is refused with
// a fingerprint for an explicit trust step, a changed key is refused outright,
// and there is no insecure ignore-host-key fallback anywhere in the codebase.
package sshprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// PinnedKey is a stored host key the resolver returns for a server.
type PinnedKey struct {
	Algorithm   string
	Fingerprint string
	PublicKey   []byte
}

// HostKeyResolver loads the pinned host key for a server. It returns
// (nil, nil) when no key has been pinned yet.
type HostKeyResolver interface {
	Pinned(ctx context.Context, serverID domain.ServerID) (*PinnedKey, error)
}

// Options configures the provider.
type Options struct {
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	MaxOutputBytes int64
}

func (o Options) connectTimeout() time.Duration {
	if o.ConnectTimeout > 0 {
		return o.ConnectTimeout
	}
	return 10 * time.Second
}

// allowed host key, kex, cipher and MAC algorithms (Design Spec §9.5). SHA-1
// variants are deliberately absent.
var (
	allowedHostKeyAlgos = []string{
		xssh.KeyAlgoED25519, xssh.KeyAlgoRSASHA512, xssh.KeyAlgoRSASHA256, xssh.KeyAlgoECDSA256,
	}
	allowedKeyExchanges = []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
	}
	allowedCiphers = []string{
		"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
	}
	allowedMACs = []string{
		"umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
	}
)

// Provider is one SSH connection.
type Provider struct {
	resolver HostKeyResolver
	opts     Options

	mu     sync.Mutex
	client *xssh.Client
	status provider.ConnectionStatus
}

// New builds an unconnected provider.
func New(resolver HostKeyResolver, opts Options) *Provider {
	return &Provider{resolver: resolver, opts: opts, status: provider.StatusDisconnected}
}

// NewFactory returns a factory that creates SSH providers.
func NewFactory(resolver HostKeyResolver, opts Options) provider.Factory {
	return func() provider.ServerExecutionProvider { return New(resolver, opts) }
}

// ID implements provider.ServerExecutionProvider.
func (p *Provider) ID() string { return "ssh" }

// Status implements provider.ServerExecutionProvider.
func (p *Provider) Status() provider.ConnectionStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// Connect establishes the SSH connection, verifying the host key against the
// pinned key (or refusing an unknown one).
func (p *Provider) Connect(ctx context.Context, t domain.Target, creds provider.CredentialSource) error {
	p.mu.Lock()
	if p.client != nil {
		p.mu.Unlock()
		return nil
	}
	p.status = provider.StatusConnecting
	p.mu.Unlock()

	cfg, err := p.clientConfig(ctx, t, creds)
	if err != nil {
		p.setStatus(provider.StatusFailed)
		return err
	}

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	dialer := &net.Dialer{Timeout: p.opts.connectTimeout()}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.setStatus(provider.StatusFailed)
		return mapNetworkError("dial", err)
	}

	c, chans, reqs, err := xssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		p.setStatus(provider.StatusFailed)
		// Host-key errors must survive unwrapped so the service can prompt.
		var hk *provider.HostKeyError
		if errors.As(err, &hk) {
			return hk
		}
		return mapHandshakeError("handshake", err)
	}

	p.mu.Lock()
	p.client = xssh.NewClient(c, chans, reqs)
	p.status = provider.StatusConnected
	p.mu.Unlock()
	return nil
}

// Disconnect closes the connection.
func (p *Provider) Disconnect(context.Context) error {
	p.mu.Lock()
	client := p.client
	p.client = nil
	p.status = provider.StatusDisconnected
	p.mu.Unlock()
	if client != nil {
		return client.Close()
	}
	return nil
}

// Ping measures round-trip latency with a keepalive request.
func (p *Provider) Ping(ctx context.Context) (time.Duration, error) {
	client, err := p.connected()
	if err != nil {
		return 0, err
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, _, rerr := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- rerr
	}()
	select {
	case <-ctx.Done():
		return 0, provider.NewError(provider.CodeTimeout, "ping", ctx.Err())
	case rerr := <-done:
		if rerr != nil {
			return 0, mapNetworkError("ping", rerr)
		}
		return time.Since(start), nil
	}
}

// Exec runs a command to completion, capturing stdout, stderr and exit status.
func (p *Provider) Exec(ctx context.Context, cmd provider.Command) (*provider.ExecResult, error) {
	client, err := p.connected()
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, mapNetworkError("exec", err)
	}
	defer func() { _ = session.Close() }()

	limit := cmd.EffectiveMaxOutput()
	if p.opts.MaxOutputBytes > 0 && p.opts.MaxOutputBytes < limit {
		limit = p.opts.MaxOutputBytes
	}
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: limit}
	session.Stdout = stdout
	session.Stderr = stderr
	session.Stdin = cmd.Stdin
	for _, e := range cmd.Env {
		_ = session.Setenv(e, "")
	}

	timeout := cmd.EffectiveTimeout()
	if p.opts.CommandTimeout > 0 && timeout == provider.DefaultCommandTimeout {
		timeout = p.opts.CommandTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	if err := session.Start(buildCommand(cmd)); err != nil {
		return nil, mapNetworkError("exec.start", err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case <-runCtx.Done():
		_ = session.Signal(xssh.SIGKILL)
		_ = session.Close()
		<-done
		if ctx.Err() != nil {
			return nil, provider.NewError(provider.CodeTimeout, "exec", ctx.Err())
		}
		return nil, provider.NewError(provider.CodeTimeout, "exec", runCtx.Err())
	case werr := <-done:
		res := &provider.ExecResult{
			Stdout:    stdout.buf.Bytes(),
			Stderr:    stderr.buf.Bytes(),
			Duration:  time.Since(start),
			Truncated: stdout.truncated || stderr.truncated,
		}
		var exitErr *xssh.ExitError
		if errors.As(werr, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		if werr != nil {
			return nil, mapNetworkError("exec.wait", werr)
		}
		return res, nil
	}
}

// ExecStream runs a command and streams its combined output.
func (p *Provider) ExecStream(ctx context.Context, cmd provider.Command) (io.ReadCloser, error) {
	client, err := p.connected()
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, mapNetworkError("exec.stream", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, mapNetworkError("exec.stream", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		return nil, mapNetworkError("exec.stream", err)
	}
	if err := session.Start(buildCommand(cmd)); err != nil {
		_ = session.Close()
		return nil, mapNetworkError("exec.stream", err)
	}
	return &execStream{reader: io.MultiReader(stdout, stderr), session: session}, nil
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

func (p *Provider) connected() (*xssh.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == nil {
		return nil, provider.NewError(provider.CodeServerOffline, "use", errors.New("not connected"))
	}
	return p.client, nil
}

func (p *Provider) setStatus(s provider.ConnectionStatus) {
	p.mu.Lock()
	p.status = s
	p.mu.Unlock()
}

func (p *Provider) clientConfig(ctx context.Context, t domain.Target, creds provider.CredentialSource) (*xssh.ClientConfig, error) {
	var pinned *PinnedKey
	if p.resolver != nil {
		var err error
		pinned, err = p.resolver.Pinned(ctx, t.ID)
		if err != nil {
			return nil, provider.NewError(provider.CodeInvalidConfig, "resolve-host-key", err)
		}
	}

	auth, err := authMethods(creds)
	if err != nil {
		return nil, err
	}

	return &xssh.ClientConfig{
		User:              t.Username,
		Auth:              auth,
		HostKeyCallback:   hostKeyCallback(t, pinned),
		HostKeyAlgorithms: allowedHostKeyAlgos,
		Config: xssh.Config{
			KeyExchanges: allowedKeyExchanges,
			Ciphers:      allowedCiphers,
			MACs:         allowedMACs,
		},
		Timeout: p.opts.connectTimeout(),
	}, nil
}

// hostKeyCallback fails closed: it only accepts the exact pinned key.
func hostKeyCallback(t domain.Target, pinned *PinnedKey) xssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key xssh.PublicKey) error {
		fp := xssh.FingerprintSHA256(key)
		if pinned == nil {
			return &provider.HostKeyError{
				Code: provider.CodeHostKeyUnknown, Host: t.Host,
				Algorithm: key.Type(), Fingerprint: fp, PublicKey: key.Marshal(),
			}
		}
		if pinned.Fingerprint != fp || !bytes.Equal(pinned.PublicKey, key.Marshal()) {
			return &provider.HostKeyError{
				Code: provider.CodeHostKeyMismatch, Host: t.Host,
				Algorithm: key.Type(), Fingerprint: fp, Expected: pinned.Fingerprint,
				PublicKey: key.Marshal(),
			}
		}
		return nil
	}
}

func authMethods(creds provider.CredentialSource) ([]xssh.AuthMethod, error) {
	if creds == nil {
		return nil, provider.NewError(provider.CodeInvalidConfig, "auth", errors.New("no credentials supplied"))
	}
	var methods []xssh.AuthMethod
	if pk := creds.PrivateKey(); pk.IsSet() {
		var signer xssh.Signer
		var err error
		if pass := creds.Passphrase(); pass.IsSet() {
			signer, err = xssh.ParsePrivateKeyWithPassphrase(pk.RevealBytes(), pass.RevealBytes())
		} else {
			signer, err = xssh.ParsePrivateKey(pk.RevealBytes())
		}
		if err != nil {
			return nil, provider.NewError(provider.CodeAuthentication, "auth", fmt.Errorf("private key could not be parsed: %w", err))
		}
		methods = append(methods, xssh.PublicKeys(signer))
	}
	if pw := creds.Password(); pw.IsSet() {
		methods = append(methods, xssh.Password(pw.Reveal()))
	}
	if len(methods) == 0 {
		return nil, provider.NewError(provider.CodeAuthentication, "auth", errors.New("credential carried no usable material"))
	}
	return methods, nil
}

// buildCommand joins the path and args with POSIX single-quote escaping. The
// SSH exec channel passes a single string to the remote shell, so arguments
// must be quoted; untrusted values never reach it unescaped (Design Spec §9.3).
func buildCommand(cmd provider.Command) string {
	parts := make([]string, 0, len(cmd.Args)+1)
	parts = append(parts, shellQuote(cmd.Path))
	for _, a := range cmd.Args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

func mapNetworkError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return provider.NewError(provider.CodeTimeout, op, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return provider.NewError(provider.CodeTimeout, op, err)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return provider.NewError(provider.CodeDNS, op, err)
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return provider.NewError(provider.CodeNetworkUnreachable, op, err)
	case strings.Contains(msg, "no such host"):
		return provider.NewError(provider.CodeDNS, op, err)
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "timeout"):
		return provider.NewError(provider.CodeTimeout, op, err)
	}
	return provider.NewError(provider.CodeServerOffline, op, err)
}

func mapHandshakeError(op string, err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods"):
		return provider.NewError(provider.CodeAuthentication, op, err)
	case strings.Contains(msg, "handshake failed"):
		return provider.NewError(provider.CodeProtocol, op, err)
	case strings.Contains(msg, "connection refused"):
		return provider.NewError(provider.CodeNetworkUnreachable, op, err)
	}
	return provider.NewError(provider.CodeProtocol, op, err)
}

// limitedBuffer is a bounded writer used for stdout and stderr. Each stream
// gets its own buffer: x/crypto/ssh copies them in separate goroutines, so a
// shared buffer would be a data race (Design Spec §9.4).
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	remaining := w.limit - int64(w.buf.Len())
	if remaining <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		w.buf.Write(p[:remaining])
		w.truncated = true
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

type execStream struct {
	reader  io.Reader
	session *xssh.Session
	once    sync.Once
}

func (s *execStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

func (s *execStream) Close() error {
	var err error
	s.once.Do(func() {
		_ = s.session.Signal(xssh.SIGKILL)
		err = s.session.Close()
	})
	return err
}
