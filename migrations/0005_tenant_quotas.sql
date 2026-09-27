-- Durable per-tenant resource quota limits.
-- Usage is derived transactionally from active sandbox rows; this table stores policy only.
CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    max_active_sandboxes integer NOT NULL CHECK (max_active_sandboxes > 0),
    max_vcpus integer NOT NULL CHECK (max_vcpus > 0),
    max_memory_mb bigint NOT NULL CHECK (max_memory_mb > 0),
    max_disk_mb bigint NOT NULL CHECK (max_disk_mb > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tenant_quotas_updated_idx
    ON tenant_quotas(updated_at DESC);

INSERT INTO tenant_quotas
    (tenant_id, max_active_sandboxes, max_vcpus, max_memory_mb, max_disk_mb)
SELECT id, 8, 32, 65536, 1048576
FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;
