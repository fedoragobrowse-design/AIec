-- The actual worker must satisfy the request throughout allocation and recovery.
ALTER TABLE sandboxes ADD COLUMN required_capabilities jsonb NOT NULL
  DEFAULT '{"exec":true,"files":true}'::jsonb
  CHECK (jsonb_typeof(required_capabilities) = 'object');

-- A fresh attempt owns its own compute and preserves its evidence after retries.
ALTER TABLE run_attempts ADD COLUMN placement jsonb NOT NULL DEFAULT '{}'::jsonb
  CHECK (jsonb_typeof(placement) = 'object');
ALTER TABLE run_attempts ADD COLUMN results jsonb NOT NULL DEFAULT '{}'::jsonb
  CHECK (jsonb_typeof(results) = 'object');

-- Missing/malformed measurements lend no capacity; stale workers still owe
-- every reservation until lease reconciliation actually releases it.
CREATE FUNCTION aiec_host_has_headroom(
  host text, memory_demand bigint, disk_demand bigint, ttl_seconds bigint
) RETURNS boolean LANGUAGE sql STABLE AS $$
  WITH siblings AS (
    SELECT last_heartbeat >= now() - ttl_seconds * interval '1 second' AS fresh,
      GREATEST(total_memory_bytes - available_memory_bytes, 0) AS held_memory,
      GREATEST(total_disk_bytes - available_disk_bytes, 0) AS held_disk,
      CASE WHEN metadata #>> '{pressure,memory_available_bytes}' ~ '^[0-9]{1,20}$'
        THEN (metadata #>> '{pressure,memory_available_bytes}')::numeric END AS memory,
      CASE WHEN metadata #>> '{pressure,disk_available_bytes}' ~ '^[0-9]{1,20}$'
        THEN (metadata #>> '{pressure,disk_available_bytes}')::numeric END AS disk
    FROM nodes WHERE metadata #>> '{pressure,host_id}' = host
  )
  SELECT COALESCE(
    length(host) > 0 AND memory_demand >= 0 AND disk_demand >= 0
    AND COUNT(*) FILTER (WHERE fresh AND memory IS NOT NULL AND disk IS NOT NULL) > 0
    AND MIN(memory) FILTER (WHERE fresh AND memory IS NOT NULL AND disk IS NOT NULL)
      - SUM(held_memory) >= memory_demand
    AND MIN(disk) FILTER (WHERE fresh AND memory IS NOT NULL AND disk IS NOT NULL)
      - SUM(held_disk) >= disk_demand,
    false)
  FROM siblings;
$$;

CREATE INDEX nodes_pressure_host_idx ON nodes ((metadata #>> '{pressure,host_id}'));
