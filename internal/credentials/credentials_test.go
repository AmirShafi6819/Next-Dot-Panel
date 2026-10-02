package credentials

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/crypto"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/secret"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

func newTestStore(t *testing.T) (*Store, repos.Queries) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dir, "creds.db"), MaxConns: 1},
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	enc, err := crypto.NewEncryptor(key, 1, nil)
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	return New(repos.NewSQLiteQueries(lite.New(db.DB)), enc), repos.NewSQLiteQueries(lite.New(db.DB))
}

func makeServer(t *testing.T, q repos.Queries, name string) domain.ServerID {
	t.Helper()
	s, err := q.CreateServer(context.Background(), repos.CreateServerParams{
		Name: name, TargetType: domain.TargetSSH, Host: "127.0.0.1", Port: 22,
		Username: "root", AuthMethod: domain.AuthPassword, HostKeyPolicy: domain.HostKeyTOFU, Tags: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	return s.ID
}

func TestCredentialRoundTrip(t *testing.T) {
	store, q := newTestStore(t)
	ctx := context.Background()
	id := makeServer(t, q, "s1")

	if _, err := store.Put(ctx, id, domain.AuthPassword, Material{Password: secret.New("hunter2")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	u, err := store.Unwrap(ctx, id)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	defer u.Close()
	if u.Password().Reveal() != "hunter2" {
		t.Fatal("password did not round-trip")
	}
	if u.PrivateKey().IsSet() {
		t.Fatal("unexpected private key")
	}
}

func TestCredentialEmptyRejected(t *testing.T) {
	store, q := newTestStore(t)
	id := makeServer(t, q, "s1")
	if _, err := store.Put(context.Background(), id, domain.AuthPassword, Material{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Put(empty) = %v, want ErrEmpty", err)
	}
}

func TestCredentialMissing(t *testing.T) {
	store, q := newTestStore(t)
	id := makeServer(t, q, "s1")
	if _, err := store.Unwrap(context.Background(), id); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("Unwrap(missing) = %v, want ErrNoCredential", err)
	}
}

func TestCredentialRotateBumpsVersion(t *testing.T) {
	store, q := newTestStore(t)
	ctx := context.Background()
	id := makeServer(t, q, "s1")
	if _, err := store.Put(ctx, id, domain.AuthPassword, Material{Password: secret.New("first")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := store.Rotate(ctx, id, domain.AuthPassword, Material{Password: secret.New("second")}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	u, err := store.Unwrap(ctx, id)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	defer u.Close()
	if u.Password().Reveal() != "second" {
		t.Fatal("rotation did not take effect")
	}
	if u.Version != 2 {
		t.Fatalf("version = %d, want 2", u.Version)
	}
}

func TestCredentialWrongKeyFailsClosed(t *testing.T) {
	store, q := newTestStore(t)
	ctx := context.Background()
	id := makeServer(t, q, "s1")
	if _, err := store.Put(ctx, id, domain.AuthPassword, Material{Password: secret.New("hunter2")}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A store with a different key must fail closed, not return garbage.
	otherKey, _ := crypto.GenerateKey()
	otherEnc, _ := crypto.NewEncryptor(otherKey, 1, nil)
	other := New(q, otherEnc)
	if _, err := other.Unwrap(ctx, id); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Unwrap with wrong key = %v, want ErrDecrypt", err)
	}
}
