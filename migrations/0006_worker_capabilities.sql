-- Persist runtime capabilities as a first-class worker scheduling contract.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capabilities jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS nodes_runtime_capabilities_idx ON nodes(runtime, capabilities);
