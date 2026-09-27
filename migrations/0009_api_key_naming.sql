-- Self-service API key management for public alpha.
--
-- A stranger must be able to list and revoke their own keys from the
-- dashboard, and a key must carry a human-recognisable name so revoking the
-- right one is possible. The secret itself is never stored: only its digest
-- already lives in api_keys.digest.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS name text;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at timestamptz;

-- Names are for humans, not identifiers, so a generous cap and an empty-string
-- guard is the right constraint.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'api_keys_name_length') THEN
    ALTER TABLE api_keys ADD CONSTRAINT api_keys_name_length
      CHECK (name IS NULL OR char_length(name) <= 80);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys(tenant_id, created_at DESC);
