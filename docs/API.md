# REST API

Base path `/v1`. Except health/metrics, send `Authorization: Bearer af_live_...`. JSON uses `snake_case`; errors are `{"error":{"code":"...","message":"...","request_id":"..."}}`. Every response includes `x-operation-id`; clients may supply a UUID in that header, otherwise the server generates one. This correlation header is not yet propagated into structured logs.

## Sandboxes

- `POST /v1/sandboxes` — create. Body: `image`, `cpu`, `memory_mb`, `disk_mb`, `timeout_seconds`, `network.enabled`.
  `environment.workspace` accepts `{"type":"empty"}` or `{"type":"git","repo":"https://...","reference":"main","shallow":true}`. Repository credentials in URLs are rejected. `environment.toolkits` is a bounded list of named `setup_commands` argv arrays.
- `GET /v1/sandboxes` — tenant list.
- `GET /v1/sandboxes/{id}` — tenant-scoped detail.
- `DELETE /v1/sandboxes/{id}` — destroy.
- `POST /v1/sandboxes/{id}/start|pause|stop|resume` — explicit lifecycle operations. `pause` is supported by Firecracker PATCH semantics; development Bubblewrap returns `501`.
  Rust SDK: `AIecClient::pause(id)` (crate `aiec-client`) / `resume(id)`; Python SDK: `Sandbox.pause()` / `Sandbox.resume()`.
- `POST /v1/sandboxes/{id}/git/diff` — return bounded `git diff --binary` for a running Git workspace.
- `POST /v1/sandboxes/{id}/exec` — body `command` argv, `working_directory`, `environment`, `timeout_seconds`, `stdin`. Returns exit code, bounded stdout/stderr, duration, timeout flag.
- `PUT /v1/sandboxes/{id}/files` — body `path`, `content_base64`, optional `mode`.
- `PUT|DELETE /v1/sandboxes/{id}/secrets/{name}` and `GET /v1/sandboxes/{id}/secrets` manage one-hour, per-sandbox process environment secrets. Values are never returned by metadata endpoints.
- `GET /v1/sandboxes/{id}/files?path=/workspace` — list.
- `GET /v1/sandboxes/{id}/files/content?path=/workspace/x` — download.
- `POST /v1/sandboxes/{id}/files/mkdir` — create directory.
- `DELETE /v1/sandboxes/{id}/files` with JSON `{path}` — delete file.
- `POST /v1/sandboxes/{id}/snapshots`, `GET /v1/sandboxes/{id}/snapshots`.
- `POST /v1/snapshots/{id}/restore` — creates a new sandbox and returns it.
- `DELETE /v1/snapshots/{id}`.
- `POST|GET|DELETE /v1/sandboxes/{id}/artifacts/{name}` provides tenant-scoped upload/download/delete with a 64 MiB decoded-size limit. `GET /v1/sandboxes/{id}/artifacts` lists sorted object metadata for the development filesystem backend. The production S3 backend returns a typed `501` for listing until ListObjectsV2 support is implemented and verified.

- `GET /v1/usage` — metric totals for current tenant.

The Python SDK exposes the same size-guarded partial path as `Sandbox.upload_artifact`, `download_artifact`, and `delete_artifact`; listing remains unsupported, and the production S3 path remains unverified.

Operational endpoints: `/health`, `/ready`, `/metrics`. `POST /v1/keys`, `/v1/keys/{id}/revoke`, and `/v1/keys/{id}/rotate` are administrative bootstrap/management operations and are disabled unless `AIEC_DEV_API_KEY` bootstraps a local tenant.

## Status codes

`400` invalid JSON/path/argv/image; `401` missing/invalid/expired/revoked key; `403` missing scope or cross-tenant access (cross-tenant resources are not disclosed); `404` tenant-scoped missing resource; `409` invalid state/race; `413` upload/resource limit too large; `422` semantic validation; `429` PostgreSQL tenant quota exceeded; `500` internal; `503` runtime/dependency unavailable.
