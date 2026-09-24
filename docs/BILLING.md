# Usage and billing foundation

Usage events are append-only facts: `tenant_id`, optional `sandbox_id`, metric, signed integer quantity, and server timestamp. The API aggregates by tenant. Core metrics are `sandbox_runtime_seconds`, `vcpu_seconds`, `memory_gb_seconds`, `disk_usage_bytes`, `snapshot_bytes`, `network_bytes` when observable, and `commands_executed`.

Quantities must come from control-plane state transitions and runtime observations, not client-declared values. Corrections are compensating events, never edits. Production billing additionally needs immutable event export, currency/rate versioning, idempotency keys, reconciliation against worker telemetry, rounding rules, and an auditable invoice pipeline. No payment provider is integrated.
