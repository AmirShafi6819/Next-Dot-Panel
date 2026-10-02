# API Reference (v1)

Base path `/api/v1`. Authentication is the `nextpanel_session` cookie.
Every error uses the envelope:

```json
{"error": {"code": "not_found", "message": "…", "request_id": "…", "details": {}}}
```

`request_id` matches the `X-Request-ID` response header and the logs.

## Auth — `/api/v1/auth`

| Method & path | Auth | Description |
|---|---|---|
| POST `/login` `{username,password}` | no | Rate-limited. Generic `invalid_credentials` on failure. Sets session + CSRF cookies. |
| POST `/logout` | yes | Revokes the session, clears cookies. |
| POST `/password` `{current_password,new_password}` | yes | Min 12 chars; revokes other sessions. |
| POST `/reauth` `{password}` | yes | Refreshes the re-auth timestamp. |
| GET `/me` | yes | Account, permissions, `default_credentials_warning`. |
| GET `/sessions` | yes | Own sessions (`current` flagged). |
| DELETE `/sessions/{id}` | yes | Revoke own session; other users' ids are 404 (IDOR). |

## Roles — `/api/v1/roles`, `/api/v1/permissions` (users.read / users.manage)

`GET /permissions` (catalogue with descriptions), `GET/POST /roles`,
`GET/PATCH/DELETE /roles/{id}`, `PUT /roles/{id}/permissions`,
`GET/PUT /users/{id}/roles`. System roles return 409 on modification.

## Users — `/api/v1/users` (users.read / users.manage)

`GET` (search/is_active/page), `POST`, `GET/PATCH/DELETE /{id}`,
`POST /{id}/reset-password` (forces change at next login, revokes sessions),
`POST /{id}/revoke-sessions`, `GET /{id}/login-history`.
Deleting yourself or the last active admin is refused.

## Servers — `/api/v1/servers`

| Method & path | Permission | Description |
|---|---|---|
| GET `/` | any (filtered) | Only visible servers; invisible ones are omitted, never 403. |
| POST `/` | servers.create | Credential fields are write-only. |
| GET `/{id}` | visible | 404 when invisible. |
| PATCH `/{id}` | servers.update | `version` required (optimistic locking). Credential rotates when supplied. |
| DELETE `/{id}` | servers.delete | Removes panel config only — never the remote host. |
| POST `/{id}/test` | servers.connect | Returns `{status, latency_ms, detail, host_key?}`. |
| GET `/{id}/hostkeys` | servers.read | Pinned keys (fingerprints, no secrets). |
| POST `/{id}/hostkeys/trust` | servers.hostkey.manage | Pins a key the operator verified out of band. |

## Files — `/api/v1/servers/{id}/files` (files.* per operation)

`GET /?path=`, `GET /stat?path=`, `GET /content?path=` (stream),
`PUT /content?path=&mode=` (stream), `POST /mkdir|rename|delete|extract`.
Deleting `/` is refused.

## Metrics — `/api/v1/servers/{id}/metrics` (metrics.read)

`GET /latest`, `GET /?from=&to=&limit=`, `POST /collect`.
SSE: `GET /events` (`text/event-stream`, persisted state only).

## Processes — `/api/v1/servers/{id}/processes` (processes.*)

`GET /` (up to 500 rows), `POST /{pid}/signal` `{force}` (SIGTERM/SIGKILL, audited).

## Terminal — `/api/v1/servers/{id}/terminal` (terminal.open)

WebSocket. Binary frames are PTY I/O; text frames are JSON
`{type:"input"|"resize"|"close", …}`. Server sends `{type:"ready"}` then
`{type:"exit"}`.

## Audit — `/api/v1/audit` (audit.read)

`GET` with `action, result, actor_id, server_id, ip, request_id, search,
from, to, page, per_page`. Append-only; no edit or delete endpoint exists.

## Error codes (stable)

`invalid_credentials`, `unauthenticated`, `forbidden`, `not_found`,
`conflict`, `invalid_request`, `credential_required`, `password_too_short`,
`password_too_common`, `password_unchanged`, `last_admin`, `own_account`,
`system_role`, `unsafe_archive`, `too_large`, `rate_limited`,
`provider_error` (+ `code` = `DNS_ERROR`, `NETWORK_UNREACHABLE`, `TIMEOUT`,
`AUTHENTICATION_FAILED`, `HOST_KEY_MISMATCH`, `HOST_KEY_UNKNOWN`,
`SERVER_OFFLINE`, …), `internal_error`.
