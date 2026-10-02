package main

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	sshprovider "github.com/ashaibery/Next-Dot-Panel/internal/provider/ssh"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// hostKeyResolver adapts the repository's pinned host key to the SSH
// provider's resolver interface.
type hostKeyResolver struct {
	q repos.Queries
}

// Pinned returns the stored host key for a server, or (nil, nil) when none is
// pinned yet.
func (r hostKeyResolver) Pinned(ctx context.Context, serverID domain.ServerID) (*sshprovider.PinnedKey, error) {
	key, err := r.q.GetHostKey(ctx, serverID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sshprovider.PinnedKey{
		Algorithm:   key.Algorithm,
		Fingerprint: key.Fingerprint,
		PublicKey:   key.PublicKey,
	}, nil
}

// registerProviders installs the execution providers the panel supports.
func registerProviders(reg *provider.Registry, q repos.Queries, cfg *config.Config) {
	reg.Register(domain.TargetSSH, sshprovider.NewFactory(
		hostKeyResolver{q: q},
		sshprovider.Options{
			ConnectTimeout: cfg.Timeouts.SSHConnect,
			CommandTimeout: cfg.Timeouts.Command,
			MaxOutputBytes: cfg.Limits.MaxCommandOutputBytes,
		},
	))
}
