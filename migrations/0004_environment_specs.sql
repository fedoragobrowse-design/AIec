-- Persist the requested composable environment with each sandbox.
ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS environment jsonb NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sandboxes_environment_object') THEN
    ALTER TABLE sandboxes ADD CONSTRAINT sandboxes_environment_object
      CHECK (jsonb_typeof(environment) = 'object');
  END IF;
END
$$;
