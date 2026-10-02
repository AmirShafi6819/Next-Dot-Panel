package processes

import "testing"

func TestParsePs(t *testing.T) {
	raw := []byte("  1 init Ss root 100 /sbin/init\n 42 nginx S+ www-data 5120 nginx: worker process\nbad line\n 0 x S r 0 y\n")
	procs := parsePs(raw)
	if len(procs) != 2 {
		t.Fatalf("parsed %d processes, want 2: %+v", len(procs), procs)
	}
	if procs[0].PID != 1 || procs[0].Name != "init" || procs[0].Username != "root" {
		t.Fatalf("first = %+v", procs[0])
	}
	if procs[0].MemoryRSS == nil || *procs[0].MemoryRSS != 100*1024 {
		t.Fatalf("rss = %v", procs[0].MemoryRSS)
	}
	if procs[1].Command != "nginx: worker process" {
		t.Fatalf("command = %q", procs[1].Command)
	}
}
