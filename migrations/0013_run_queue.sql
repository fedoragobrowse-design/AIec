-- Durable admission and short executor ownership; VM I/O never holds these locks.
ALTER TABLE runs ADD CONSTRAINT runs_tenant_id_id_unique UNIQUE (tenant_id, id);

CREATE TABLE run_queue_tenants (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  last_dispatched_at timestamptz
);

CREATE TABLE run_queue (
  run_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object'),
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'executing', 'reclaiming', 'finished')),
  enqueued_at timestamptz NOT NULL DEFAULT now(),
  queue_deadline timestamptz NOT NULL,
  execution_seconds bigint NOT NULL CHECK (execution_seconds > 0),
  execution_deadline timestamptz,
  owner uuid,
  lease_until timestamptz,
  failure_reason text,
  FOREIGN KEY (tenant_id, run_id) REFERENCES runs(tenant_id, id) ON DELETE CASCADE,
  CHECK ((status IN ('executing', 'reclaiming') AND owner IS NOT NULL AND lease_until IS NOT NULL)
    OR (status IN ('queued', 'finished') AND owner IS NULL AND lease_until IS NULL)),
  CHECK (status <> 'executing' OR execution_deadline IS NOT NULL)
);
CREATE INDEX run_queue_pending_tenant_idx ON run_queue(tenant_id, enqueued_at, run_id)
  WHERE status <> 'finished';
CREATE INDEX run_queue_recovery_idx ON run_queue(status, lease_until, queue_deadline)
  WHERE status <> 'finished';

-- Old active Runs have no complete request/owner and cannot safely be replayed.
-- Give recovery an expired teardown-only grant, preserving all Run/attempt evidence.
INSERT INTO run_queue_tenants(tenant_id)
  SELECT DISTINCT tenant_id FROM runs
  WHERE state IN ('queued', 'preparing', 'running', 'validating', 'collecting');
INSERT INTO run_queue(run_id, tenant_id, request, status, queue_deadline,
  execution_seconds, owner, lease_until, failure_reason)
  SELECT id, tenant_id, '{}'::jsonb, 'reclaiming', now(), 720,
    id, '-infinity'::timestamptz, 'Run executor ownership unavailable after queue migration'
  FROM runs WHERE state IN ('queued', 'preparing', 'running', 'validating', 'collecting');
