package sshprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/secret"
)

// ---------------------------------------------------------------------------
// test doubles
// ---------------------------------------------------------------------------

type testCreds struct {
	pk secret.Secret
	pw secret.Secret
}

func (c testCreds) Password() secret.Secret   { return c.pw }
func (c testCreds) PrivateKey() secret.Secret { return c.pk }
func (c testCreds) Passphrase() secret.Secret { return secret.Empty() }
func (c testCreds) Close()                    {}

type staticResolver struct{ key *PinnedKey }

func (r staticResolver) Pinned(context.Context, domain.ServerID) (*PinnedKey, error) {
	return r.key, nil
}

type testSSHServer struct {
	listener net.Listener
	cfg      *xssh.ServerConfig
	handler  func(cmd string) (stdout, stderr string, code int, delay time.Duration)
}

func startSSHServer(t *testing.T, hostSigner xssh.Signer, authorized xssh.PublicKey, handler func(string) (string, string, int, time.Duration)) *testSSHServer {
	t.Helper()
	cfg := &xssh.ServerConfig{
		PublicKeyCallback: func(_ xssh.ConnMetadata, key xssh.PublicKey) (*xssh.Permissions, error) {
			if authorized != nil && bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown public key")
		},
	}
	cfg.AddHostKey(hostSigner)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSSHServer{listener: l, cfg: cfg, handler: handler}
	go s.serve()
	t.Cleanup(func() { _ = l.Close() })
	return s
}

func (s *testSSHServer) addr() (string, int) {
	host, portStr, _ := net.SplitHostPort(s.listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func (s *testSSHServer) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func (s *testSSHServer) handleConn(c net.Conn) {
	conn, chans, reqs, err := xssh.NewServerConn(c, s.cfg)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go xssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(xssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleChan(ch, chReqs)
	}
}

func (s *testSSHServer) handleChan(ch xssh.Channel, reqs <-chan *xssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			_ = xssh.Unmarshal(req.Payload, &payload)
			_ = req.Reply(true, nil)
			out, errOut, code, delay := s.handler(payload.Command)
			if delay > 0 {
				time.Sleep(delay)
			}
			if out != "" {
				_, _ = ch.Write([]byte(out))
			}
			if errOut != "" {
				_, _ = ch.Stderr().Write([]byte(errOut))
			}
			status := struct{ Status uint32 }{uint32(code)}
			_, _ = ch.SendRequest("exit-status", false, xssh.Marshal(&status))
			return
		case "env", "pty-req", "shell":
			_ = req.Reply(true, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func generateKey(t *testing.T) (ed25519.PrivateKey, xssh.Signer, xssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	sshPub, err := xssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return priv, signer, sshPub
}

func privateKeyPEM(t *testing.T, priv ed25519.PrivateKey) secret.Secret {
	t.Helper()
	block, err := xssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return secret.New(string(pem.EncodeToMemory(block)))
}

func pinnedFrom(signer xssh.Signer) *PinnedKey {
	pk := signer.PublicKey()
	return &PinnedKey{Algorithm: pk.Type(), Fingerprint: xssh.FingerprintSHA256(pk), PublicKey: pk.Marshal()}
}

func target(host string, port int) domain.Target {
	return domain.Target{ID: 1, Type: domain.TargetSSH, Host: host, Port: port, Username: "tester", AuthMethod: domain.AuthKey, HostKeyPolicy: domain.HostKeyStrict}
}

func connect(t *testing.T, p *Provider, tg domain.Target, key secret.Secret) error {
	t.Helper()
	creds := testCreds{pk: key}
	return p.Connect(context.Background(), tg, creds)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestUnknownHostKeyRefused(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, echoHandler)
	host, port := srv.addr()

	p := New(staticResolver{key: nil}, Options{})
	err := connect(t, p, target(host, port), privateKeyPEM(t, priv))
	if !provider.IsUnknownHostKey(err) {
		t.Fatalf("Connect = %v, want unknown host key", err)
	}
	var hk *provider.HostKeyError
	if !errors.As(err, &hk) || hk.Fingerprint == "" || len(hk.PublicKey) == 0 {
		t.Fatalf("host key error missing fingerprint/material: %+v", hk)
	}
	if p.Status() != provider.StatusFailed {
		t.Fatalf("status = %s, want FAILED", p.Status())
	}
}

func TestPinnedHostKeyAcceptedAndPing(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, echoHandler)
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(hostSigner)}, Options{})
	if err := connect(t, p, target(host, port), privateKeyPEM(t, priv)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = p.Disconnect(context.Background()) }()
	if p.Status() != provider.StatusConnected {
		t.Fatalf("status = %s, want CONNECTED", p.Status())
	}
	if _, err := p.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestChangedHostKeyHardStop(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	_, otherSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, echoHandler)
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(otherSigner)}, Options{})
	err := connect(t, p, target(host, port), privateKeyPEM(t, priv))
	if !provider.IsHostKeyMismatch(err) {
		t.Fatalf("Connect = %v, want host key mismatch", err)
	}
	if p.Status() != provider.StatusFailed {
		t.Fatalf("status = %s, want FAILED", p.Status())
	}
}

func TestAuthenticationFailure(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, _ := generateKey(t)     // client key
	_, _, otherPub := generateKey(t) // server authorises a different key
	srv := startSSHServer(t, hostSigner, otherPub, echoHandler)
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(hostSigner)}, Options{})
	err := connect(t, p, target(host, port), privateKeyPEM(t, priv))
	if provider.CodeOf(err) != provider.CodeAuthentication {
		t.Fatalf("Connect code = %s (%v), want AUTHENTICATION_FAILED", provider.CodeOf(err), err)
	}
}

func TestExecSuccessAndStreams(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, echoHandler)
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(hostSigner)}, Options{})
	if err := connect(t, p, target(host, port), privateKeyPEM(t, priv)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = p.Disconnect(context.Background()) }()

	res, err := p.Exec(context.Background(), provider.Command{Path: "echo", Args: []string{"hello world"}})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "hello world") {
		t.Fatalf("result = %+v, want stdout hello world", res)
	}
	if res.Duration < 0 {
		t.Fatal("duration was not measured")
	}
}

func TestExecNonZeroExitIsAResult(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, func(cmd string) (string, string, int, time.Duration) {
		return "", "boom", 3, 0
	})
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(hostSigner)}, Options{})
	if err := connect(t, p, target(host, port), privateKeyPEM(t, priv)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = p.Disconnect(context.Background()) }()

	res, err := p.Exec(context.Background(), provider.Command{Path: "false"})
	if err != nil {
		t.Fatalf("Exec returned an error for a non-zero exit: %v", err)
	}
	if res.ExitCode != 3 || !strings.Contains(string(res.Stderr), "boom") {
		t.Fatalf("result = %+v, want exit 3 and stderr boom", res)
	}
}

func TestExecTimeout(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, func(string) (string, string, int, time.Duration) {
		return "", "", 0, 500 * time.Millisecond
	})
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(hostSigner)}, Options{})
	if err := connect(t, p, target(host, port), privateKeyPEM(t, priv)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = p.Disconnect(context.Background()) }()

	_, err := p.Exec(context.Background(), provider.Command{Path: "sleep", Args: []string{"1"}, Timeout: 50 * time.Millisecond})
	if provider.CodeOf(err) != provider.CodeTimeout {
		t.Fatalf("Exec code = %s (%v), want TIMEOUT", provider.CodeOf(err), err)
	}
}

func TestExecContextCancellation(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, func(string) (string, string, int, time.Duration) {
		return "", "", 0, 500 * time.Millisecond
	})
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(hostSigner)}, Options{})
	if err := connect(t, p, target(host, port), privateKeyPEM(t, priv)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = p.Disconnect(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := p.Exec(ctx, provider.Command{Path: "sleep", Args: []string{"1"}, Timeout: 5 * time.Second})
	if provider.CodeOf(err) != provider.CodeTimeout {
		t.Fatalf("Exec code = %s (%v), want TIMEOUT", provider.CodeOf(err), err)
	}
}

func TestExecOutputTruncation(t *testing.T) {
	_, hostSigner, _ := generateKey(t)
	priv, _, userPub := generateKey(t)
	srv := startSSHServer(t, hostSigner, userPub, func(string) (string, string, int, time.Duration) {
		return strings.Repeat("x", 100), "", 0, 0
	})
	host, port := srv.addr()

	p := New(staticResolver{key: pinnedFrom(hostSigner)}, Options{MaxOutputBytes: 10})
	if err := connect(t, p, target(host, port), privateKeyPEM(t, priv)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = p.Disconnect(context.Background()) }()

	res, err := p.Exec(context.Background(), provider.Command{Path: "yes"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !res.Truncated || len(res.Stdout) > 10 {
		t.Fatalf("output not truncated: len=%d truncated=%v", len(res.Stdout), res.Truncated)
	}
}

func TestMapNetworkErrorCodes(t *testing.T) {
	cases := []struct {
		msg  string
		want provider.ErrorCode
	}{
		{"dial tcp 127.0.0.1:22: connectex: No connection could be made because the target machine actively refused it.", provider.CodeNetworkUnreachable},
		{"dial tcp: lookup nope.invalid: no such host", provider.CodeDNS},
		{"i/o timeout", provider.CodeTimeout},
	}
	for _, tc := range cases {
		if got := provider.CodeOf(mapNetworkError("dial", errors.New(tc.msg))); got != tc.want {
			t.Errorf("mapNetworkError(%q) = %s, want %s", tc.msg, got, tc.want)
		}
	}
}

func echoHandler(cmd string) (string, string, int, time.Duration) {
	switch {
	case strings.HasPrefix(cmd, "echo"):
		return "hello world\n", "", 0, 0
	case cmd == "false":
		return "", "", 1, 0
	default:
		return "ok\n", "", 0, 0
	}
}
