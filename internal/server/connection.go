package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/credentials"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Connect authorizes the actor for perm on the server and returns a connected
// provider plus the credential source. The caller must Close the credential
// source. The provider stays pooled for reuse; callers do not disconnect it.
//
// This is the single gateway every feature (exec, files, terminal, metrics,
// processes) uses, so the authorization and credential-unwrapping logic exists
// once.
func (s *Service) Connect(ctx context.Context, actor auth.Actor, id domain.ServerID, perm domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error) {
	srv, err := s.loadVisible(ctx, actor, id)
	if err != nil {
		return nil, nil, err
	}
	if err := s.authz.Require(ctx, actor, perm, &id); err != nil {
		return nil, nil, ErrNotFound
	}

	var src provider.CredentialSource
	if srv.Target.Type == domain.TargetSSH && (srv.Target.AuthMethod == domain.AuthKey || srv.Target.AuthMethod == domain.AuthPassword) {
		unwrapped, uerr := s.creds.Unwrap(ctx, id)
		if uerr != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, uerr)
		}
		src = unwrapped
	}

	p, err := s.reg.For(ctx, srv.Target)
	if err != nil {
		if src != nil {
			src.Close()
		}
		return nil, nil, err
	}
	if err := p.Connect(ctx, srv.Target, src); err != nil {
		if src != nil {
			src.Close()
		}
		return nil, nil, err
	}
	return p, src, nil
}

// Exec runs a command on a server. Requires servers.connect. The exit code is
// a result, not an error; transport failures are returned as errors.
func (s *Service) Exec(ctx context.Context, actor auth.Actor, id domain.ServerID, cmd provider.Command, meta Meta) (*provider.ExecResult, error) {
	p, src, err := s.Connect(ctx, actor, id, domain.PermServersConnect)
	if err != nil {
		return nil, err
	}
	if src != nil {
		defer src.Close()
	}
	if cmd.MaxOutputBytes == 0 {
		cmd.MaxOutputBytes = s.opts.MaxCommandOutputBytes
	}
	res, err := p.Exec(ctx, cmd)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// HostKeyPrompt is presented when a connection is refused because the host key
// is unknown. The operator must explicitly trust it before the connection is
// retried (Design Spec §9.1).
type HostKeyPrompt struct {
	Algorithm   string
	Fingerprint string
	PublicKey   []byte
}

// ConnectionResult is the outcome of a connection test. A failed connection is
// a result, not an error: the test completed and recorded a status.
type ConnectionResult struct {
	Server  domain.Server
	Status  domain.ServerStatus
	Latency time.Duration
	Detail  string
	HostKey *HostKeyPrompt
}

// TestConnection connects to a server, pings it, discovers basic system info
// and records the resulting status. Requires servers.connect on the server.
func (s *Service) TestConnection(ctx context.Context, actor auth.Actor, id domain.ServerID, meta Meta) (ConnectionResult, error) {
	srv, err := s.loadVisible(ctx, actor, id)
	if err != nil {
		return ConnectionResult{}, err
	}
	if err := s.authz.Require(ctx, actor, domain.PermServersConnect, &id); err != nil {
		return ConnectionResult{}, ErrNotFound
	}

	var src provider.CredentialSource
	if srv.Target.Type == domain.TargetSSH && (srv.Target.AuthMethod == domain.AuthKey || srv.Target.AuthMethod == domain.AuthPassword) {
		unwrapped, uerr := s.creds.Unwrap(ctx, id)
		if errors.Is(uerr, credentials.ErrNoCredential) {
			return s.fail(ctx, actor, srv, meta, provider.NewError(provider.CodeInvalidConfig, "connect", errors.New("no credential stored")))
		}
		if uerr != nil {
			return s.fail(ctx, actor, srv, meta, provider.NewError(provider.CodeInvalidConfig, "connect", uerr))
		}
		defer unwrapped.Close()
		src = unwrapped
	}

	p, err := s.reg.For(ctx, srv.Target)
	if err != nil {
		return s.fail(ctx, actor, srv, meta, err)
	}
	if err := p.Connect(ctx, srv.Target, src); err != nil {
		return s.fail(ctx, actor, srv, meta, err)
	}
	latency, err := p.Ping(ctx)
	if err != nil {
		return s.fail(ctx, actor, srv, meta, err)
	}

	s.discover(ctx, p, srv.ID)

	updated, err := s.q.UpdateServerStatus(ctx, repos.UpdateServerStatusParams{
		ID: id, Status: domain.StatusOnline, Detail: "",
	})
	if err != nil {
		return ConnectionResult{}, fmt.Errorf("server: record status: %w", err)
	}
	s.record(ctx, actor, domain.ActionServerConnectionOK, updated, meta, domain.ResultSuccess,
		map[string]any{"latency_ms": latency.Milliseconds()})
	return ConnectionResult{Server: updated, Status: domain.StatusOnline, Latency: latency}, nil
}

// TrustHostKey pins a host key the operator has explicitly accepted. It
// replaces any previous pin, which is the only path that accepts a changed
// key; connecting never does this implicitly (Design Spec §9.1). Requires
// servers.hostkey.manage on the server.
func (s *Service) TrustHostKey(ctx context.Context, actor auth.Actor, id domain.ServerID, algorithm, fingerprint string, publicKey []byte, meta Meta) error {
	srv, err := s.loadVisible(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := s.authz.Require(ctx, actor, domain.PermServersHostKey, &id); err != nil {
		return ErrNotFound
	}
	if algorithm == "" || fingerprint == "" || len(publicKey) == 0 {
		return ErrInvalid
	}
	if err := s.q.DeleteHostKeys(ctx, id); err != nil {
		return fmt.Errorf("server: clear host keys: %w", err)
	}
	now := time.Now()
	if _, err := s.q.CreateHostKey(ctx, repos.CreateHostKeyParams{
		ServerID: id, Algorithm: algorithm, Fingerprint: fingerprint, PublicKey: publicKey,
		State: domain.HostKeyTrusted, TrustedAt: &now, TrustedBy: &actor.UserID,
	}); err != nil {
		return fmt.Errorf("server: pin host key: %w", err)
	}
	s.reg.Invalidate(ctx, id)
	s.record(ctx, actor, domain.ActionHostKeyTrusted, srv, meta, domain.ResultSuccess,
		map[string]any{"algorithm": algorithm, "fingerprint": fingerprint})
	return nil
}

// ListHostKeys returns the pinned keys for a server the actor can see.
func (s *Service) ListHostKeys(ctx context.Context, actor auth.Actor, id domain.ServerID) ([]domain.HostKey, error) {
	if _, err := s.loadVisible(ctx, actor, id); err != nil {
		return nil, err
	}
	if err := s.authz.Require(ctx, actor, domain.PermServersRead, &id); err != nil {
		return nil, ErrNotFound
	}
	keys, err := s.q.ListHostKeys(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("server: list host keys: %w", err)
	}
	return keys, nil
}

// discover records OS/kernel/arch from `uname`. Failure is not fatal: a server
// that connects but cannot run uname is still online.
func (s *Service) discover(ctx context.Context, p provider.ServerExecutionProvider, id domain.ServerID) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := p.Exec(ctx, provider.Command{Path: "uname", Args: []string{"-srm"}, Timeout: 5 * time.Second})
	if err != nil || res.ExitCode != 0 {
		return
	}
	fields := strings.Fields(strings.TrimSpace(string(res.Stdout)))
	if len(fields) < 3 {
		return
	}
	if err := s.q.UpdateServerSystemInfo(ctx, repos.UpdateServerSystemInfoParams{
		ID: id, OS: fields[0], Kernel: fields[1], Arch: fields[2],
	}); err != nil && s.log != nil {
		s.log.Warn(ctx, "recording server system info failed", "server_id", id, "error", err)
	}
}

// fail records an unsuccessful connection and returns it as a result.
func (s *Service) fail(ctx context.Context, actor auth.Actor, srv domain.Server, meta Meta, err error) (ConnectionResult, error) {
	code := provider.CodeOf(err)
	status := domain.StatusError
	switch code {
	case provider.CodeNetworkUnreachable, provider.CodeDNS, provider.CodeTimeout, provider.CodeServerOffline:
		status = domain.StatusOffline
	case provider.CodeHostKeyUnknown, provider.CodeHostKeyMismatch:
		status = domain.StatusError
	}

	updated, uerr := s.q.UpdateServerStatus(ctx, repos.UpdateServerStatusParams{
		ID: srv.ID, Status: status, Detail: string(code),
	})
	if uerr != nil {
		return ConnectionResult{}, fmt.Errorf("server: record status: %w", uerr)
	}

	var prompt *HostKeyPrompt
	var hk *provider.HostKeyError
	if errors.As(err, &hk) {
		prompt = &HostKeyPrompt{Algorithm: hk.Algorithm, Fingerprint: hk.Fingerprint, PublicKey: hk.PublicKey}
	}
	extra := map[string]any{"error_code": string(code)}
	if prompt != nil {
		extra["fingerprint"] = prompt.Fingerprint
	}
	s.record(ctx, actor, domain.ActionServerConnectionFailed, updated, meta, domain.ResultFailure, extra)
	return ConnectionResult{Server: updated, Status: status, Detail: string(code), HostKey: prompt}, nil
}
