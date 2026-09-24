-- AgentForge production control-plane metadata.
-- Every statement is safe to re-run so operators can repair partially applied deployments.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE nodes ADD COLUMN IF NOT EXISTS total_vcpus integer;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS total_memory_bytes bigint;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS total_disk_bytes bigint;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS runtime text NOT NULL DEFAULT 'firecracker';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS control_endpoint text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS started_at timestamptz NOT NULL DEFAULT now();

UPDATE nodes
SET total_vcpus = available_vcpus
WHERE total_vcpus IS NULL;
UPDATE nodes
SET total_memory_bytes = available_memory_bytes
WHERE total_memory_bytes IS NULL;
UPDATE nodes
SET total_disk_bytes = available_disk_bytes
WHERE total_disk_bytes IS NULL;

ALTER TABLE nodes ALTER COLUMN total_vcpus SET NOT NULL;
ALTER TABLE nodes ALTER COLUMN total_memory_bytes SET NOT NULL;
ALTER TABLE nodes ALTER COLUMN total_disk_bytes SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'nodes_total_vcpus_nonnegative'
  ) THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_total_vcpus_nonnegative CHECK (total_vcpus >= 0);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'nodes_total_memory_nonnegative'
  ) THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_total_memory_nonnegative CHECK (total_memory_bytes >= 0);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'nodes_total_disk_nonnegative'
  ) THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_total_disk_nonnegative CHECK (total_disk_bytes >= 0);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'nodes_capacity_within_total'
  ) THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_capacity_within_total CHECK (
      available_vcpus <= total_vcpus
      AND available_memory_bytes <= total_memory_bytes
      AND available_disk_bytes <= total_disk_bytes
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_sandbox_count_nonnegative') THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_sandbox_count_nonnegative CHECK (sandbox_count >= 0);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'nodes_version_positive') THEN
    ALTER TABLE nodes ADD CONSTRAINT nodes_version_positive CHECK (version > 0);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS nodes_schedulable_idx
  ON nodes(healthy, last_heartbeat DESC, available_vcpus, available_memory_bytes, available_disk_bytes);

ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'filesystem';
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS manifest_object_key text;
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS memory_object_key text;
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS disk_object_key text;
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS workspace_object_key text;
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS checksum_sha256 text;
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS manifest jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS complete boolean NOT NULL DEFAULT false;

UPDATE snapshots
SET manifest_object_key = object_key
WHERE manifest_object_key IS NULL;
UPDATE snapshots
SET complete = true
WHERE checksum_sha256 IS NOT NULL;

ALTER TABLE snapshots ALTER COLUMN manifest_object_key SET NOT NULL;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'snapshots_checksum_sha256_format') THEN
    ALTER TABLE snapshots ADD CONSTRAINT snapshots_checksum_sha256_format
      CHECK (checksum_sha256 IS NULL OR checksum_sha256 ~ '^[0-9A-Fa-f]{64}$');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'snapshots_kind_nonempty') THEN
    ALTER TABLE snapshots ADD CONSTRAINT snapshots_kind_nonempty CHECK (length(kind) > 0);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'snapshots_complete_bundle') THEN
    ALTER TABLE snapshots ADD CONSTRAINT snapshots_complete_bundle CHECK (
      NOT complete OR (
        checksum_sha256 IS NOT NULL
        AND memory_object_key IS NOT NULL
        AND disk_object_key IS NOT NULL
        AND workspace_object_key IS NOT NULL
      )
    );
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS snapshots_tenant_kind_idx
  ON snapshots(tenant_id, kind, created_at DESC);

CREATE TABLE IF NOT EXISTS sandbox_requests (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  request_id uuid NOT NULL,
  sandbox_id uuid NOT NULL REFERENCES sandboxes(id),
  fingerprint bytea NOT NULL CHECK(octet_length(fingerprint) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id, request_id),
  UNIQUE(tenant_id, sandbox_id)
);

CREATE TABLE IF NOT EXISTS sandbox_leases (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  sandbox_id uuid NOT NULL REFERENCES sandboxes(id),
  node_id uuid NOT NULL REFERENCES nodes(id),
  generation bigint NOT NULL DEFAULT 1 CHECK(generation > 0),
  status text NOT NULL CHECK(status IN ('active', 'completed', 'released', 'expired')),
  reason text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sandbox_leases_tenant_idx
  ON sandbox_leases(tenant_id, id);
CREATE INDEX IF NOT EXISTS sandbox_leases_expiry_idx
  ON sandbox_leases(status, expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS sandbox_leases_one_active_per_sandbox
  ON sandbox_leases(sandbox_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS sandbox_assignments (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  request_id uuid NOT NULL,
  sandbox_id uuid NOT NULL REFERENCES sandboxes(id),
  node_id uuid NOT NULL REFERENCES nodes(id),
  lease_id uuid NOT NULL REFERENCES sandbox_leases(id),
  status text NOT NULL CHECK(status IN ('reserved', 'assigned', 'completed', 'released', 'expired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id, request_id),
  UNIQUE(tenant_id, sandbox_id, lease_id)
);
CREATE INDEX IF NOT EXISTS sandbox_assignments_tenant_status_idx
  ON sandbox_assignments(tenant_id, status, created_at);
CREATE INDEX IF NOT EXISTS sandbox_assignments_node_status_idx
  ON sandbox_assignments(node_id, status, created_at);

CREATE TABLE IF NOT EXISTS operation_requests (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  request_id uuid NOT NULL,
  sandbox_id uuid NOT NULL REFERENCES sandboxes(id),
  operation text NOT NULL,
  payload jsonb NOT NULL,
  status text NOT NULL CHECK(status IN ('pending', 'succeeded', 'failed')),
  result jsonb,
  error jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(tenant_id, request_id)
);
CREATE INDEX IF NOT EXISTS operation_requests_sandbox_idx
  ON operation_requests(tenant_id, sandbox_id, created_at DESC);

CREATE TABLE IF NOT EXISTS reconciliation_actions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  node_id uuid NOT NULL REFERENCES nodes(id),
  sandbox_id uuid REFERENCES sandboxes(id),
  lease_id uuid REFERENCES sandbox_leases(id),
  source_key text NOT NULL UNIQUE,
  action text NOT NULL,
  reason text NOT NULL,
  detected_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reconciliation_actions_tenant_idx
  ON reconciliation_actions(tenant_id, detected_at DESC);

-- Every tenant-owned child row must reference a sandbox owned by that same tenant.
-- Separate tenant and sandbox foreign keys are insufficient for isolation.
CREATE UNIQUE INDEX IF NOT EXISTS sandboxes_id_tenant_unique
  ON sandboxes(id, tenant_id);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandbox_events_tenant_sandbox_fk') THEN
    ALTER TABLE sandbox_events ADD CONSTRAINT sandbox_events_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'snapshots_tenant_sandbox_fk') THEN
    ALTER TABLE snapshots ADD CONSTRAINT snapshots_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'usage_events_tenant_sandbox_fk') THEN
    ALTER TABLE usage_events ADD CONSTRAINT usage_events_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandbox_requests_tenant_sandbox_fk') THEN
    ALTER TABLE sandbox_requests ADD CONSTRAINT sandbox_requests_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandbox_leases_tenant_sandbox_fk') THEN
    ALTER TABLE sandbox_leases ADD CONSTRAINT sandbox_leases_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandbox_assignments_tenant_sandbox_fk') THEN
    ALTER TABLE sandbox_assignments ADD CONSTRAINT sandbox_assignments_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'operation_requests_tenant_sandbox_fk') THEN
    ALTER TABLE operation_requests ADD CONSTRAINT operation_requests_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'reconciliation_tenant_sandbox_fk') THEN
    ALTER TABLE reconciliation_actions ADD CONSTRAINT reconciliation_tenant_sandbox_fk
      FOREIGN KEY (sandbox_id, tenant_id) REFERENCES sandboxes(id, tenant_id);
  END IF;
END
$$;

-- Usage is a billing ledger. Corrections must be compensating append-only events.
CREATE OR REPLACE FUNCTION agentforge_reject_usage_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'usage_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS usage_events_append_only ON usage_events;
CREATE TRIGGER usage_events_append_only
BEFORE UPDATE OR DELETE ON usage_events
FOR EACH ROW EXECUTE FUNCTION agentforge_reject_usage_mutation();
