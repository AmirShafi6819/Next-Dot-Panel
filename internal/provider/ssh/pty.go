package sshprovider

import (
	"context"
	"errors"
	"io"
	"sync"

	xssh "golang.org/x/crypto/ssh"

	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
)

// OpenPTY opens an interactive shell on a pseudo-terminal.
func (p *Provider) OpenPTY(_ context.Context, o provider.PTYOptions) (provider.PTY, error) {
	client, err := p.connected()
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, mapNetworkError("pty", err)
	}

	term := o.Term
	if term == "" {
		term = "xterm-256color"
	}
	cols, rows := o.Cols, o.Rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	modes := xssh.TerminalModes{
		xssh.ECHO:          1,
		xssh.TTY_OP_ISPEED: 14400,
		xssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty(term, int(rows), int(cols), modes); err != nil {
		_ = session.Close()
		return nil, mapNetworkError("pty.request", err)
	}
	for _, e := range o.Env {
		_ = session.Setenv(e, "")
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, mapNetworkError("pty.stdin", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, mapNetworkError("pty.stdout", err)
	}
	// A PTY is the controlling terminal, so the remote shell merges stderr into
	// the same stream; capturing stdout alone is correct here.
	if err := session.Shell(); err != nil {
		_ = session.Close()
		return nil, mapNetworkError("pty.shell", err)
	}
	return &sshPTY{session: session, stdin: stdin, stdout: stdout}, nil
}

type sshPTY struct {
	session *xssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	once    sync.Once
}

func (t *sshPTY) Read(p []byte) (int, error)  { return t.stdout.Read(p) }
func (t *sshPTY) Write(p []byte) (int, error) { return t.stdin.Write(p) }

func (t *sshPTY) Resize(_ context.Context, cols, rows uint16) error {
	return t.session.WindowChange(int(rows), int(cols))
}

func (t *sshPTY) Wait() (int, error) {
	err := t.session.Wait()
	var exitErr *xssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	if err != nil {
		return -1, mapNetworkError("pty.wait", err)
	}
	return 0, nil
}

func (t *sshPTY) Close() error {
	var err error
	t.once.Do(func() {
		_ = t.stdin.Close()
		err = t.session.Close()
	})
	return err
}
