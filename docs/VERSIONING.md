# Versioning and compatibility

AgentForge is pre-1.0. Core source compatibility is not promised yet, and extension authors must pin the workspace version while Core contracts evolve.

## Independently versioned boundaries

- **Core Rust API:** domain types and public traits. Adding a required trait method or changing a method signature is breaking for every backend implementor.
- **Backend implementation API:** constructors, backend configuration, and concrete types. These may evolve independently unless a type is also a documented Core contract.
- **Guest protocol:** negotiated or explicitly versioned on the wire. Incompatible peers must fail with a typed error, not be inferred.
- **Worker protocol:** request/response envelopes, operation names, authentication, limits, and idempotency rules. Changes require matching API/worker rollout compatibility.
- **Snapshot format:** persisted memory, VM state, disk, and manifest compatibility. Format changes require explicit version metadata and migration/rejection behavior.
- **Image manifest format:** persisted image identity and rootfs metadata. It evolves independently of the image resolver implementation.

Patch releases must not silently reinterpret persisted snapshot or image data. Backend crates must keep SQLx, Firecracker, Linux, and AWS types behind Core signatures. See `EXTENDING.md` for the compile-time extension model and `ARCHITECTURE.md` for dependency direction.
