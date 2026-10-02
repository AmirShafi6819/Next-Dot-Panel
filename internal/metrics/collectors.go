// Package metrics implements server resource monitoring. Collection reads
// /proc through the provider (no shell interpolation of anything
// user-controlled) and persists samples to the repository; the frontend
// subscribes over SSE (Design Spec §18, §28).
//
// A missing metric is never represented as zero: pointers distinguish absent
// data from a real reading (Design Spec §18.4).
package metrics

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Gateway is the connection gateway (satisfied by *server.Service).
type Gateway interface {
	Connect(ctx context.Context, actor auth.Actor, id domain.ServerID, perm domain.Permission) (provider.ServerExecutionProvider, provider.CredentialSource, error)
}

// Authorizer enforces permissions (satisfied by *rbac.Service).
type Authorizer interface {
	Require(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) error
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
}

// Service collects and queries metrics.
type Service struct {
	q interface {
		UpsertMetricSample(ctx context.Context, s domain.MetricSample) error
		UpsertMetricFilesystem(ctx context.Context, fs domain.Filesystem) error
		GetLatestMetricSample(ctx context.Context, serverID domain.ServerID) (domain.MetricSample, error)
		ListMetricSamples(ctx context.Context, p repos.MetricRangeParams) ([]domain.MetricSample, error)
		ListLatestFilesystems(ctx context.Context, serverID domain.ServerID) ([]domain.Filesystem, error)
	}
	gw    Gateway
	authz Authorizer
	audit *audit.Writer
	log   logger

	mu   sync.Mutex
	prev map[domain.ServerID]*cpuCounters

	// Now supplies timestamps; tests replace it.
	Now func() time.Time
}

// New builds the metrics service. q is repos.Queries; the anonymous interface
// lists only what this package uses so tests can substitute it.
func New(q repos.Queries, gw Gateway, authz Authorizer, auditWriter *audit.Writer, log logger) *Service {
	return &Service{q: q, gw: gw, authz: authz, audit: auditWriter, log: log, prev: map[domain.ServerID]*cpuCounters{}, Now: time.Now}
}

var errCollect = errors.New("metrics: collection failed")

// CollectNow gathers one sample for a server. Requires metrics.read. CPU
// usage needs two readings, so the first collection leaves CPUPct empty and
// the delta is computed from the previous in-memory reading.
func (s *Service) CollectNow(ctx context.Context, actor auth.Actor, id domain.ServerID) (domain.MetricSample, []domain.Filesystem, error) {
	p, src, err := s.gw.Connect(ctx, actor, id, domain.PermMetricsRead)
	if err != nil {
		return domain.MetricSample{}, nil, err
	}
	if src != nil {
		defer src.Close()
	}

	// /proc files are small; read them over SFTP so no shell is involved.
	read := func(name string) ([]byte, error) {
		rc, rerr := p.OpenRead(ctx, name, 0)
		if rerr != nil {
			return nil, rerr
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(io.LimitReader(rc, 1<<20))
	}

	statRaw, statErr := read("/proc/stat")
	memRaw, memErr := read("/proc/meminfo")
	loadRaw, _ := read("/proc/loadavg")
	uptimeRaw, _ := read("/proc/uptime")
	netRaw, _ := read("/proc/net/dev")

	if statErr != nil || memErr != nil {
		return domain.MetricSample{}, nil, fmt.Errorf("%w: /proc is not readable", errCollect)
	}

	cur := parseCPUCounters(statRaw)
	s.mu.Lock()
	cpu := cpuFromStat(cur, s.prev[id])
	if cur != nil && cur.valid {
		s.prev[id] = cur
	}
	s.mu.Unlock()

	mem := parseMeminfo(memRaw)
	load1, load5, load15 := parseLoadavg(loadRaw)
	uptime := parseUptime(uptimeRaw)
	rx, tx := parseNetDev(netRaw)

	sample := domain.MetricSample{
		ServerID:      id,
		Timestamp:     s.Now(),
		CPUPct:        cpu,
		Load1:         load1,
		Load5:         load5,
		Load15:        load15,
		MemTotal:      mem.total,
		MemAvailable:  mem.available,
		MemCached:     mem.cached,
		MemBuffers:    mem.buffers,
		SwapTotal:     mem.swapTotal,
		SwapUsed:      subOrNil(mem.swapTotal, mem.swapFree),
		NetRxBytes:    rx,
		NetTxBytes:    tx,
		UptimeSeconds: uptime,
	}

	fs, _ := s.collectDisks(ctx, p)
	for i := range fs {
		fs[i].ServerID = id
		fs[i].Timestamp = sample.Timestamp
	}
	return sample, fs, nil
}

func subOrNil(a, b *int64) *int64 {
	if a == nil || b == nil {
		return nil
	}
	v := *a - *b
	if v < 0 {
		v = 0
	}
	return &v
}

// ---------------------------------------------------------------------------
// /proc parsers (all defensive: malformed output yields nil, never a panic)
// ---------------------------------------------------------------------------

type cpuCounters struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
	valid                                                 bool
}

func parseCPUCounters(raw []byte) *cpuCounters {
	if len(raw) == 0 {
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		if len(fields) < 4 {
			return nil
		}
		nums := make([]uint64, len(fields))
		for i, f := range fields {
			n, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return nil
			}
			nums[i] = n
		}
		c := &cpuCounters{valid: true}
		c.user, c.nice, c.system, c.idle = nums[0], nums[1], nums[2], nums[3]
		if len(nums) > 4 {
			c.iowait = nums[4]
		}
		if len(nums) > 5 {
			c.irq = nums[5]
		}
		if len(nums) > 6 {
			c.softirq = nums[6]
		}
		if len(nums) > 7 {
			c.steal = nums[7]
		}
		return c
	}
	return nil
}

func cpuTotal(c *cpuCounters) uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

// cpuFromStat computes a usage fraction from two readings. It returns nil when
// only one reading exists (first collection) or the delta is not positive.
func cpuFromStat(cur, prev *cpuCounters) *float64 {
	if cur == nil || !cur.valid || prev == nil || !prev.valid {
		return nil
	}
	totalDelta := cpuTotal(cur) - cpuTotal(prev)
	idleDelta := (cur.idle + cur.iowait) - (prev.idle + prev.iowait)
	if totalDelta == 0 {
		return nil
	}
	pct := 100.0 * float64(totalDelta-idleDelta) / float64(totalDelta)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return &pct
}

type memValues struct {
	total, available, cached, buffers, swapTotal, swapFree *int64
}

func parseMeminfo(raw []byte) memValues {
	var v memValues
	set := func(dst **int64, line, key string) {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != key {
			return
		}
		// Values are in kB.
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return
		}
		val := n * 1024
		*dst = &val
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		set(&v.total, line, "MemTotal:")
		set(&v.available, line, "MemAvailable:")
		set(&v.cached, line, "Cached:")
		set(&v.buffers, line, "Buffers:")
		set(&v.swapTotal, line, "SwapTotal:")
		set(&v.swapFree, line, "SwapFree:")
	}
	return v
}

func parseLoadavg(raw []byte) (l1, l5, l15 *float64) {
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return nil, nil, nil
	}
	val := func(s string) *float64 {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil
		}
		return &f
	}
	return val(fields[0]), val(fields[1]), val(fields[2])
}

func parseUptime(raw []byte) *int64 {
	fields := strings.Fields(string(raw))
	if len(fields) < 1 {
		return nil
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	v := int64(f)
	return &v
}

// parseNetDev sums receive/transmit bytes across interfaces. Counters reset
// when interfaces restart; rates are computed by the consumer from deltas and
// negative deltas are clamped to zero there.
func parseNetDev(raw []byte) (rx, tx *int64) {
	var totalRx, totalTx uint64
	found := false
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "" || iface == "lo" {
			// Loopback is not host traffic; skip it. Other virtual interfaces
			// are included on purpose (veth, docker0) since they carry real
			// bytes.
			if iface == "lo" {
				continue
			}
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		r, err1 := strconv.ParseUint(fields[0], 10, 64)
		t, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		totalRx += r
		totalTx += t
		found = true
	}
	if !found {
		return nil, nil
	}
	rv, tv := int64(totalRx), int64(totalTx)
	return &rv, &tv
}

// collectDisks gathers filesystem usage. The command is entirely static: no
// user-controlled value ever reaches it.
func (s *Service) collectDisks(ctx context.Context, p provider.ServerExecutionProvider) ([]domain.Filesystem, error) {
	res, err := p.Exec(ctx, provider.Command{
		Path: "df", Args: []string{"-P", "-T", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay"},
		Timeout: 10 * time.Second,
	})
	if err != nil || res.ExitCode != 0 {
		return nil, errCollect
	}
	return parseDf(res.Stdout), nil
}

// parseDf parses `df -P -T -B1` output. Malformed lines are skipped.
func parseDf(raw []byte) []domain.Filesystem {
	var out []domain.Filesystem
	sc := bufio.NewScanner(bytes.NewReader(raw))
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false // header
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		device, fstype := fields[0], fields[1]
		total, err1 := strconv.ParseInt(fields[2], 10, 64)
		used, err2 := strconv.ParseInt(fields[3], 10, 64)
		avail, err3 := strconv.ParseInt(fields[4], 10, 64)
		mount := fields[6]
		if err1 != nil || err2 != nil || err3 != nil || !strings.HasPrefix(mount, "/") {
			continue
		}
		var pct *float64
		if total > 0 {
			v := 100.0 * float64(used) / float64(total)
			pct = &v
		}
		out = append(out, domain.Filesystem{
			MountPoint: mount, Device: device, FSType: fstype,
			TotalBytes: &total, UsedBytes: &used, AvailBytes: &avail, UsedPct: pct,
		})
	}
	return out
}
