-- Scope snapshot completeness to the artifacts each kind actually produces.
--
-- A complete workspace snapshot is a portable workspace archive: it has no
-- memory or disk object, because those belong to VM-level capture. The previous
-- constraint required all three keys for every kind, which made a workspace
-- snapshot unstorable and blocked the recovery path that restores a sandbox's
-- durable workspace on a new owner. Migration 0002 has already been applied, so
-- the constraint is replaced here rather than edited in place.
ALTER TABLE snapshots DROP CONSTRAINT IF EXISTS snapshots_complete_bundle;

ALTER TABLE snapshots ADD CONSTRAINT snapshots_complete_bundle CHECK (
  NOT complete
  OR (
    checksum_sha256 IS NOT NULL
    AND workspace_object_key IS NOT NULL
    AND (
      kind = 'workspace'
      OR (memory_object_key IS NOT NULL AND disk_object_key IS NOT NULL)
    )
  )
);
