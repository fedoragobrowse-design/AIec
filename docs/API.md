# REST API

Base path `/v1`. Except health/metrics, send `Authorization: Bearer af_live_...`. JSON uses `snake_case`; errors are `{"error":{"code":"...","message":"...","request_id":"..."}}`.

## Sandboxes

- `POST /v1/sandboxes` — create. Body: `image`, `cpu`, `memory_mb`, `disk_mb`, `timeout_seconds`, `network.enabled`.
- `GET /v1/sandboxes` — tenant list.
- `GET /v1/sandboxes/{id}` — tenant-scoped detail.
- `DELETE /v1/sandboxes/{id}` — destroy.
- `POST /v1/sandboxes/{id}/start|stop|resume` — lifecycle; stopped/failed start is idempotent where safe.
- `POST /v1/sandboxes/{id}/exec` — body `command` argv, `working_directory`, `environment`, `timeout_seconds`, `stdin`. Returns exit code, bounded stdout/stderr, duration, timeout flag.
- `PUT /v1/sandboxes/{id}/files` — body `path`, `content_base64`, optional `mode`.
- `GET /v1/sandboxes/{id}/files?path=/workspace` — list.
- `GET /v1/sandboxes/{id}/files/content?path=/workspace/x` — download.
- `POST /v1/sandboxes/{id}/files/mkdir` — create directory.
- `DELETE /v1/sandboxes/{id}/files` with JSON `{path}` — delete file.
- `POST /v1/sandboxes/{id}/snapshots`, `GET /v1/sandboxes/{id}/snapshots`.
- `POST /v1/snapshots/{id}/restore` — creates a new sandbox and returns it.
- `DELETE /v1/snapshots/{id}`.
- `GET /v1/usage` — metric totals for current tenant.

Operational endpoints: `/health`, `/ready`, `/metrics`. `POST /v1/keys`, `/v1/keys/{id}/revoke`, and `/v1/keys/{id}/rotate` are administrative bootstrap/management operations and are disabled unless `AGENTFORGE_DEV_API_KEY` bootstraps a local tenant.

## Status codes

`400` invalid JSON/path/argv/image; `401` missing/invalid/expired/revoked key; `403` missing scope or cross-tenant access (cross-tenant resources are not disclosed); `404` tenant-scoped missing resource; `409` invalid state/race; `413` upload too large; `422` semantic validation; `429` future rate limit; `500` internal; `503` runtime/dependency unavailable.
