-- The orchestration layer: a Run is a durable piece of work, not a sandbox.
--
-- A sandbox is compute that already exists. A run is work being executed using
-- compute, and it is the thing a caller actually asks for. Keeping them apart is
-- what lets a run span several clean machines, survive one of them failing, and
-- still be addressable after every machine it used is gone.
--
-- Nothing here duplicates the sandbox tables. A run references sandboxes; it
-- does not embed or shadow them.

CREATE TABLE IF NOT EXISTS runs (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  state text NOT NULL CHECK (state IN (
    'queued', 'preparing', 'running', 'validating', 'collecting',
    'succeeded', 'failed', 'cancelled'
  )),

  requested_at timestamptz NOT NULL DEFAULT now(),
  queued_at timestamptz,
  started_at timestamptz,
  completed_at timestamptz,

  -- The work, in one document so a run can be created and read back without a
  -- join. Validated in code against the same rules the sandbox API applies.
  workload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(workload) = 'object'),
  environment jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(environment) = 'object'),
  requirements jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(requirements) = 'object'),
  resources jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(resources) = 'object'),

  -- Why this run was placed where it was, as a list of reasons a human reads.
  -- Kept because "the scheduler refused it" is the hardest thing to debug.
  placement jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(placement) = 'object'),

  results jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(results) = 'object'),
  failure_reason text,

  -- Retention. A failed run can keep its machine for debugging, but never
  -- forever: `expires_at` is what the reaper acts on, and it is always set.
  retention text NOT NULL DEFAULT 'destroy'
    CHECK (retention IN ('destroy', 'keep_on_failure', 'keep_always')),
  retained_sandbox_id uuid,
  retained_until timestamptz,

  -- The caller's idempotency key. Two requests with the same key produce one
  -- run, so a retried request cannot double-bill or double-execute.
  idempotency_key text,

  parent_run_id uuid REFERENCES runs(id) ON DELETE SET NULL,
  matrix_id uuid
);

-- A run may use several sandboxes: a comparison, a batch, or a retry after a
-- failure all produce more than one machine under a single run.
CREATE TABLE IF NOT EXISTS run_sandboxes (
  run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  sandbox_id uuid NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
  -- What this machine was for, so a reader can tell a retry from a parallel leg.
  role text NOT NULL DEFAULT 'primary',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (run_id, sandbox_id)
);

-- Every try. A run that failed and was retried keeps the evidence of the
-- attempts that did not work; collapsing them would lose the reason it failed.
CREATE TABLE IF NOT EXISTS run_attempts (
  id uuid PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  attempt_number integer NOT NULL CHECK (attempt_number > 0),
  sandbox_id uuid REFERENCES sandboxes(id) ON DELETE SET NULL,
  state text NOT NULL CHECK (state IN ('running', 'succeeded', 'failed', 'cancelled')),
  failure_reason text,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  UNIQUE (run_id, attempt_number)
);

-- The run's own history. Separate from audit_log on purpose: audit_log answers
-- "who touched what and was it allowed", this answers "what happened to this
-- piece of work", and the two are read at very different rates.
CREATE TABLE IF NOT EXISTS run_events (
  id uuid PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  sandbox_id uuid,
  -- run.created, sandbox.assigned, task.started, artifact.collected, ...
  type text NOT NULL CHECK (length(type) > 0),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  -- Shapes and names, never values: this is written to disk and read by anyone
  -- with database access.
  detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object')
);

CREATE TABLE IF NOT EXISTS run_artifacts (
  id uuid PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  -- The path as it appeared inside the sandbox, which is what a reader expects.
  name text NOT NULL CHECK (length(name) > 0),
  object_key text NOT NULL,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  checksum_sha256 text,
  content_type text,
  collected_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, name)
);

-- Indexes for the paths that are actually queried rather than every column.
-- "Runs for this tenant, newest first" and "history of this run" are the two
-- reads that happen on every page of the UI and every debug session.
CREATE INDEX IF NOT EXISTS runs_tenant_created_idx
  ON runs(tenant_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS runs_state_queued_idx
  ON runs(state, queued_at)
  WHERE state IN ('queued', 'preparing', 'running', 'validating', 'collecting');
CREATE INDEX IF NOT EXISTS runs_matrix_idx ON runs(matrix_id) WHERE matrix_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS runs_parent_idx ON runs(parent_run_id) WHERE parent_run_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS runs_idempotency_idx
  ON runs(tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS runs_retained_until_idx
  ON runs(retained_until)
  WHERE retained_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS run_events_run_time_idx
  ON run_events(run_id, occurred_at);
CREATE INDEX IF NOT EXISTS run_events_sandbox_idx
  ON run_events(sandbox_id) WHERE sandbox_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS run_attempts_run_idx ON run_attempts(run_id, attempt_number);
CREATE INDEX IF NOT EXISTS run_attempts_sandbox_idx
  ON run_attempts(sandbox_id) WHERE sandbox_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS run_sandboxes_sandbox_idx ON run_sandboxes(sandbox_id);
CREATE INDEX IF NOT EXISTS run_artifacts_run_idx ON run_artifacts(run_id, name);

-- A run's history is append-only in the same sense audit_log is: the record of
-- what happened must not be editable after the fact, or it is not evidence.
CREATE OR REPLACE FUNCTION aiec_reject_run_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'run_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS run_events_append_only ON run_events;
CREATE TRIGGER run_events_append_only
BEFORE UPDATE OR DELETE ON run_events
FOR EACH ROW EXECUTE FUNCTION aiec_reject_run_event_mutation();

DROP TRIGGER IF EXISTS run_events_reject_truncate ON run_events;
CREATE TRIGGER run_events_reject_truncate
BEFORE TRUNCATE ON run_events
FOR EACH STATEMENT EXECUTE FUNCTION aiec_reject_run_event_mutation();
