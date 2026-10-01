-- Durable upload ownership and deletion intents. Keep tombstones so a stale
-- collector or delayed PUT can never make a deleted key a new live reference.
ALTER TABLE runs ADD COLUMN artifacts_expired_at timestamptz;
CREATE INDEX runs_artifact_expiry_idx ON runs(completed_at, id)
  WHERE state IN ('succeeded','failed','cancelled') AND artifacts_expired_at IS NULL;
CREATE INDEX run_artifacts_object_key_idx ON run_artifacts(object_key);
CREATE INDEX runs_results_artifacts_idx ON runs USING gin ((results->'artifacts'));
CREATE INDEX snapshots_artifact_keys_idx ON snapshots USING gin
  ((ARRAY[object_key,manifest_object_key,memory_object_key,disk_object_key,workspace_object_key]));

CREATE TABLE artifact_objects (
  object_key text PRIMARY KEY CHECK (length(object_key) BETWEEN 1 AND 1024),
  tenant_id uuid NOT NULL,
  owner_run_id uuid,
  state text NOT NULL CHECK (state IN ('pending','available','deleting','deleted')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  claim uuid,
  lease_until timestamptz,
  retry_at timestamptz NOT NULL DEFAULT now(),
  attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
-- Deliberately no cascading foreign keys: external deletion must survive owner
-- metadata removal, including tenant removal.
--
-- The sweep reads a bounded keyset window of this index and decides eligibility
-- for that window alone. The window is therefore bounded by the batch size, not
-- by how many protected objects happen to sort in front of the garbage, and a
-- protected prefix never starves the keys behind it: the window wraps.
CREATE INDEX artifact_objects_scan_idx ON artifact_objects(object_key)
  WHERE state <> 'deleted';
CREATE INDEX artifact_objects_owner_idx ON artifact_objects(owner_run_id);

-- One row carries the continuation key of the bounded sweep. A sweeper holds it
-- for the duration of its pass, so two passes never advance the same window
-- twice, and a page that ends short resumes at the start of the ledger instead
-- of restarting the object population from its lowest key.
CREATE TABLE artifact_gc_scan (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  last_object_key text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO artifact_gc_scan (id) VALUES (true);

INSERT INTO artifact_objects(object_key, tenant_id, owner_run_id, state)
SELECT DISTINCT ON (object_key) object_key, tenant_id, owner_run_id, 'available'
FROM (
  SELECT a.object_key, r.tenant_id, a.run_id AS owner_run_id
    FROM run_artifacts a JOIN runs r ON r.id = a.run_id
  UNION ALL
  SELECT a.artifact->>'object_key', r.tenant_id, r.id
    FROM runs r, LATERAL jsonb_array_elements(COALESCE(r.results->'artifacts','[]'::jsonb)) AS a(artifact)
    WHERE a.artifact->>'object_key' IS NOT NULL
  UNION ALL
  SELECT key, s.tenant_id, NULL::uuid FROM snapshots s,
    LATERAL unnest(ARRAY[s.object_key,s.manifest_object_key,s.memory_object_key,
      s.disk_object_key,s.workspace_object_key]) AS keys(key) WHERE key IS NOT NULL
) AS object_references
ORDER BY object_key, owner_run_id NULLS LAST;

-- Every reference creator takes the object row lock, exactly as deletion claims
-- do. A reference cannot appear between the final check and external deletion.
CREATE FUNCTION aiec_lock_artifact_reference(key text, tenant uuid, owner_run uuid)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE object_state text;
BEGIN
  INSERT INTO artifact_objects(object_key, tenant_id, owner_run_id, state)
  VALUES (key, tenant, owner_run, 'available') ON CONFLICT DO NOTHING;
  SELECT state INTO object_state FROM artifact_objects WHERE object_key = key FOR UPDATE;
  IF object_state IN ('deleting','deleted') THEN
    RAISE EXCEPTION 'artifact key is being deleted or has expired' USING ERRCODE = '23514';
  END IF;
  UPDATE artifact_objects SET state = 'available', updated_at = now() WHERE object_key = key;
END;
$$;

CREATE FUNCTION aiec_guard_run_artifact_reference() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner_tenant uuid; expired timestamptz;
BEGIN
  SELECT tenant_id, artifacts_expired_at INTO owner_tenant, expired
    FROM runs WHERE id = NEW.run_id FOR UPDATE;
  IF expired IS NOT NULL THEN
    RAISE EXCEPTION 'run artifacts have expired' USING ERRCODE = '23514';
  END IF;
  PERFORM aiec_lock_artifact_reference(NEW.object_key, owner_tenant, NEW.run_id);
  RETURN NEW;
END;
$$;
CREATE TRIGGER run_artifact_reference_guard BEFORE INSERT OR UPDATE ON run_artifacts
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_run_artifact_reference();

CREATE FUNCTION aiec_guard_run_result_artifacts() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE key text;
BEGIN
  IF NEW.artifacts_expired_at IS NOT NULL AND jsonb_array_length(COALESCE(NEW.results->'artifacts','[]'::jsonb)) > 0 THEN
    RAISE EXCEPTION 'run artifacts have expired' USING ERRCODE = '23514';
  END IF;
  FOR key IN SELECT DISTINCT artifact->>'object_key'
    FROM jsonb_array_elements(COALESCE(NEW.results->'artifacts','[]'::jsonb)) AS artifacts(artifact)
    WHERE artifact->>'object_key' IS NOT NULL ORDER BY artifact->>'object_key'
  LOOP
    PERFORM aiec_lock_artifact_reference(key, NEW.tenant_id, NEW.id);
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER run_result_artifact_reference_guard BEFORE INSERT OR UPDATE OF results ON runs
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_run_result_artifacts();

CREATE FUNCTION aiec_guard_snapshot_artifact_reference() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE key text;
BEGIN
  FOR key IN SELECT DISTINCT value FROM unnest(ARRAY[NEW.object_key,
      NEW.manifest_object_key, NEW.memory_object_key, NEW.disk_object_key,
      NEW.workspace_object_key]) AS keys(value) WHERE value IS NOT NULL ORDER BY value
  LOOP
    PERFORM aiec_lock_artifact_reference(key, NEW.tenant_id, NULL);
  END LOOP;
  RETURN NEW;
END;
$$;
CREATE TRIGGER snapshot_artifact_reference_guard BEFORE INSERT OR UPDATE ON snapshots
  FOR EACH ROW EXECUTE FUNCTION aiec_guard_snapshot_artifact_reference();
