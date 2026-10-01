-- A host's logical CPUs, checked against the machine rather than the worker.
--
-- Memory and disk are stores: what a sandbox takes, it gives back when it
-- exits, so every worker on a host reads the same figures and the honest
-- question is how much of it is left. Logical CPUs are not a store. Two
-- workers on one machine each read the whole ceiling free, each is right about
-- its own worker, and together they promise more vCPUs than the host has - a
-- placement admitted on one worker and refused on the other for the same
-- request, on a machine that was never in a better state. So CPU is
-- aggregated the way the others are, with the difference stated rather than
-- hidden: the demand is capped against the *least* favourable fresh measured
-- ceiling, minus every sibling's held vCPUs (`total_vcpus - available_vcpus`
-- on that node's ledger). The readings are never summed. There is no
-- automatic oversubscription, and a host whose ceiling nobody could observe
-- lends no CPU at all, whatever it measured for memory and disk.
--
-- `measured` is the whole reading, not a per-resource question: a host that
-- reported memory and disk but no CPU ceiling is not a host with unlimited
-- CPUs, so the ceiling is part of what has to be present rather than a
-- separate question a missing answer slips past.
--
-- The reservations are still subtracted whether or not the sibling that owes
-- them is fresh, for the reason 0012 gave: something was promised against this
-- host, and forgetting the promise would make room for more.
--
-- The signature changes rather than grows an overload, because "admitted on
-- memory and disk" and "admitted on CPU as well" are not two situations an
-- operator can tell apart from a refusal: every caller must be able to see
-- that CPU is part of what it is asking. The old function is dropped here
-- rather than kept as an alias, so nothing can quietly keep placing work on
-- the two-reading answer this replaces.

CREATE FUNCTION aiec_host_has_headroom(
  host text,
  vcpu_demand bigint,
  memory_demand bigint,
  disk_demand bigint,
  ttl_seconds bigint
) RETURNS boolean LANGUAGE sql STABLE AS $$
  WITH siblings AS (
    SELECT last_heartbeat >= now() - ttl_seconds * interval '1 second' AS fresh,
      GREATEST(total_vcpus - available_vcpus, 0) AS held_vcpus,
      GREATEST(total_memory_bytes - available_memory_bytes, 0) AS held_memory,
      GREATEST(total_disk_bytes - available_disk_bytes, 0) AS held_disk,
      CASE WHEN metadata #>> '{pressure,total_vcpus}' ~ '^[0-9]{1,10}$'
        THEN (metadata #>> '{pressure,total_vcpus}')::numeric END AS ceiling,
      CASE WHEN metadata #>> '{pressure,available_vcpus}' ~ '^[0-9]{1,10}$'
        THEN (metadata #>> '{pressure,available_vcpus}')::numeric END AS cpu,
      CASE WHEN metadata #>> '{pressure,memory_available_bytes}' ~ '^[0-9]{1,20}$'
        THEN (metadata #>> '{pressure,memory_available_bytes}')::numeric END AS memory,
      CASE WHEN metadata #>> '{pressure,disk_available_bytes}' ~ '^[0-9]{1,20}$'
        THEN (metadata #>> '{pressure,disk_available_bytes}')::numeric END AS disk
    FROM nodes WHERE metadata #>> '{pressure,host_id}' = host
  ),
  readings AS (
    SELECT *,
      fresh AND ceiling IS NOT NULL AND cpu IS NOT NULL
        AND memory IS NOT NULL AND disk IS NOT NULL AS measured
    FROM siblings
  )
  SELECT COALESCE(
    length(host) > 0 AND vcpu_demand >= 0 AND memory_demand >= 0 AND disk_demand >= 0
    AND COUNT(*) FILTER (WHERE measured) > 0
    -- Capped against the least favourable fresh ceiling and what is left of
    -- it, never against a sum of readings: two workers each reporting eight
    -- free vCPUs on a sixteen-vCPU host do not make sixteen vCPUs exist.
    AND LEAST(
        MIN(ceiling) FILTER (WHERE measured),
        MIN(cpu) FILTER (WHERE measured)
      ) - COALESCE(SUM(held_vcpus), 0) >= vcpu_demand
    AND MIN(memory) FILTER (WHERE measured) - COALESCE(SUM(held_memory), 0) >= memory_demand
    AND MIN(disk) FILTER (WHERE measured) - COALESCE(SUM(held_disk), 0) >= disk_demand,
    false)
  FROM readings;
$$;

DROP FUNCTION aiec_host_has_headroom(text, bigint, bigint, bigint);
