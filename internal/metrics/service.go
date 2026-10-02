package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// SystemActor is the trusted background identity used by scheduled collection.
// It is constructed inside the process, never from a request, and holds only
// the permissions collection needs.
func SystemActor() auth.Actor {
	return auth.Actor{
		Username:    "system",
		SessionID:   "system",
		Permissions: []domain.Permission{domain.PermServersRead, domain.PermMetricsRead},
	}
}

// CollectAndPersist collects one sample and stores it.
func (s *Service) CollectAndPersist(ctx context.Context, actor auth.Actor, id domain.ServerID) error {
	sample, fs, err := s.CollectNow(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := s.q.UpsertMetricSample(ctx, sample); err != nil {
		return fmt.Errorf("metrics: persist sample: %w", err)
	}
	for _, f := range fs {
		if err := s.q.UpsertMetricFilesystem(ctx, f); err != nil {
			return fmt.Errorf("metrics: persist filesystem: %w", err)
		}
	}
	return nil
}

// Latest returns the most recent sample and filesystem snapshot. Requires
// metrics.read on the server.
func (s *Service) Latest(ctx context.Context, actor auth.Actor, id domain.ServerID) (domain.MetricSample, []domain.Filesystem, error) {
	if err := s.authz.Require(ctx, actor, domain.PermMetricsRead, &id); err != nil {
		return domain.MetricSample{}, nil, err
	}
	sample, err := s.q.GetLatestMetricSample(ctx, id)
	if err != nil {
		return domain.MetricSample{}, nil, fmt.Errorf("metrics: latest: %w", err)
	}
	fs, err := s.q.ListLatestFilesystems(ctx, id)
	if err != nil {
		return domain.MetricSample{}, nil, fmt.Errorf("metrics: filesystems: %w", err)
	}
	return sample, fs, nil
}

// Range returns samples in a window. Requires metrics.read on the server.
func (s *Service) Range(ctx context.Context, actor auth.Actor, id domain.ServerID, from, to time.Time, limit int64) ([]domain.MetricSample, error) {
	if err := s.authz.Require(ctx, actor, domain.PermMetricsRead, &id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	samples, err := s.q.ListMetricSamples(ctx, repos.MetricRangeParams{
		ServerID: id, From: from, To: to, Limit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("metrics: range: %w", err)
	}
	return samples, nil
}
