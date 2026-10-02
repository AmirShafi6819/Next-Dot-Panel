# Deployment

## Docker (recommended)

```sh
docker build -f deploy/docker/Dockerfile -t next-panel .
export NEXT_PANEL_ENCRYPTION_KEY="$(docker run --rm next-panel crypto generate-key)"
docker compose -f deploy/docker/compose.yaml up -d
```

The image builds the React UI and embeds it, runs migrations on start, and
exposes `8080` with a `/health` healthcheck. Data lives in the `panel-data`
volume (`/data`); the database file and backups survive container recreation.
For PostgreSQL, uncomment the `postgres` service and set
`NEXT_PANEL_DB_DRIVER=postgres` + `NEXT_PANEL_DB_DSN`.

## Manual Linux install

1. Install Go 1.26+ and Node 20+.
2. `git clone … && cd Next.Panel`
3. `cd web && npm ci && npm run build && cd ..`
4. `go build -o nextpanel ./cmd/nextpanel`
5. `export NEXT_PANEL_ENCRYPTION_KEY="$(./nextpanel crypto generate-key)"`
6. `export NEXT_PANEL_DATA_DIR=/var/lib/nextpanel NEXT_PANEL_ENV=production`
   `NEXT_PANEL_EXTERNAL_SCHEME=https NEXT_PANEL_LISTEN=127.0.0.1:8080`
7. Run migrations + start: `./nextpanel` (migrations run automatically).
8. Put nginx/Caddy in front (see `deploy/proxy/`), then open the UI and sign
   in as `admin` / `123456` — change the password immediately.

## systemd

Copy `deploy/systemd/nextpanel.service` to `/etc/systemd/system/`, create a
`nextpanel` user, copy `deploy/systemd/nextpanel.env.example` to
`/etc/nextpanel/nextpanel.env` with `chmod 600`, then
`systemctl enable --now nextpanel`. The unit runs unprivileged with strict
hardening; only `/var/lib/nextpanel` is writable.

## Reverse proxy

Terminate TLS at the proxy and forward plain HTTP + WebSockets. Examples with
upload sizes and 1h idle timeouts for terminals live in `deploy/proxy/`.
Set `NEXT_PANEL_EXTERNAL_SCHEME=https` so cookies are `Secure` and HSTS is
sent. Behind a proxy, only trust `X-Forwarded-*` from that proxy (the panel
itself uses the socket address for audit).

## Backups and restore

Back up the panel database file (`$NEXT_PANEL_DATA_DIR/*.db` for SQLite, or
`pg_dump` for PostgreSQL) **and** `NEXT_PANEL_ENCRYPTION_KEY` separately —
without the key, stored server credentials cannot be decrypted. Restoring is
stopping the panel, replacing the database file (or `pg_restore`), and
starting it; migrations re-apply automatically. Panel backups do not back up
your remote servers' data.

## Upgrades

Pull, rebuild, restart. Migrations are versioned and run on start; never
edit the production schema by hand. Breaking migrations are documented in
CHANGELOG.md.
