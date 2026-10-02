// Package processes lists remote processes and signals them. Listing is
// read-only; termination requires processes.signal and is audited with the
// PID, name and signal — never with a shell-constructed command (Design
// Spec §64).
package processes

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// Gateway is the connection gateway (satisfied by *server.Service).
type Gateway interface {
	Connect(ctx context.Context, actor auth.Actor, id domain.ServerID, perm domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error)
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
}

// Service manages remote processes.
type Service struct {
	gw    Gateway
	audit *audit.Writer
	log   logger
}

// New builds the processes service.
func New(gw Gateway, auditWriter *audit.Writer, log logger) *Service {
	return &Service{gw: gw, audit: auditWriter, log: log}
}

// Meta carries request context onto audit records.
type Meta struct {
	RequestID string
	IP        string
	UserAgent string
}

// List returns the remote process table. Requires processes.read.
func (s *Service) List(ctx context.Context, actor auth.Actor, id domain.ServerID) ([]domain.Process, error) {
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermProcessesRead)
	if err != nil {
		return nil, err
	}
	if src != nil {
		defer src.Close()
	}
	res, err := p.Exec(ctx, provider.Command{
		Path: "ps",
		Args: []string{"-eo", "pid=,comm=,stat=,user=,rss=,args="},
	})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("processes: ps exited %d", res.ExitCode)
	}
	return parsePs(res.Stdout), nil
}

// Signal sends SIGTERM (or SIGKILL when force is set) to a PID. Requires
// processes.signal and is audited.
func (s *Service) Signal(ctx context.Context, actor auth.Actor, id domain.ServerID, pid int, force bool, meta Meta) error {
	if pid <= 0 {
		return errors.New("processes: invalid pid")
	}
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermProcessesSignal)
	if err != nil {
		return err
	}
	if src != nil {
		defer src.Close()
	}
	sig := "-TERM"
	if force {
		sig = "-KILL"
	}
	// Both arguments are static except the validated numeric pid.
	res, err := p.Exec(ctx, provider.Command{Path: "kill", Args: []string{sig, strconv.Itoa(pid)}})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("processes: kill exited %d: %s", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	if s.audit != nil {
		sid := id
		s.audit.Record(ctx, audit.Event{
			ActorID: &actor.UserID, ActorName: actor.Username,
			Action: domain.ActionProcessTerminated, Target: fmt.Sprintf("process:%d", pid),
			ServerID: &sid, Result: domain.ResultSuccess,
			RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			Metadata: map[string]any{"signal": strings.TrimPrefix(sig, "-")},
		})
	}
	return nil
}

// parsePs parses `ps -eo pid=,comm=,stat=,user=,rss=,args=` output defensively.
// Unparseable lines are skipped.
func parsePs(raw []byte) []domain.Process {
	var out []domain.Process
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 {
			continue
		}
		rssKB, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			continue
		}
		rss := rssKB * 1024
		cmd := ""
		if len(fields) > 5 {
			cmd = strings.Join(fields[5:], " ")
		}
		out = append(out, domain.Process{
			PID: pid, Name: fields[1], State: fields[2], Username: fields[3],
			MemoryRSS: &rss, Command: cmd,
		})
	}
	return out
}
