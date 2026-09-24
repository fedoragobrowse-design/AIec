# Extending AgentForge Core

AgentForge Core is the compile-time extension boundary for infrastructure backends. The default AgentForge server, worker, scheduler, storage, image resolver, network manager, snapshot provider, and policy are selected through the same public `Platform` composition used by custom products.

## Dependency direction

```text
custom runtimes/schedulers/stores/networks/images/policies
                         |
                         v
                  AgentForge Core
                         ^
                         |
       AgentForge API / worker / CLI composition
```

Backend crates depend on Core. Core does not depend on Firecracker, Linux networking, SQLx/PostgreSQL, S3, Axum, or AWS. Products depend on Core and select concrete backends.

## Extension boundaries

A product supplies implementations of the meaningful infrastructure boundaries:

- `runtime::SandboxRuntime` controls sandbox creation, lifecycle, execution, and file operations.
- `scheduler::Scheduler` selects capacity and resolves the worker that owns a sandbox lease.
- `storage::MetadataStore` persists control-plane metadata.
- `storage::ArtifactStore` stores opaque snapshot artifacts by key.
- `network::NetworkBackend` prepares and cleans up isolated VM networking.
- `images::ImageResolver` maps an image reference to stable image metadata.
- `snapshots::SnapshotProvider` describes snapshot support and compatibility.
- `policy::PlatformPolicy` validates product-specific creation and restore rules.
- `platform::Platform` owns the selected trait objects and rejects incomplete composition.

Not every internal function is injectable. Database queries, state transitions, HTTP routes, guest frames, and worker protocol internals stay with the subsystem that owns them unless a demonstrated use case requires a boundary.

## Custom composition

Implement the traits required by the product, then pass `Arc<dyn Trait>` values to `Platform::builder()` and call `build()`. The `custom_core_platform` example uses the real `BubblewrapRuntime` and `FilesystemObjectStore` with custom scheduler, policy, and network implementations. It validates the assembled capability and artifact contracts without starting an API listener or requiring KVM.

Run it with:

```bash
cargo run -p agentforge-api --example custom_core_platform
```

## Compatibility and versioning

All crates are currently pre-1.0. Compatibility is tracked separately for these boundaries:

| Boundary | Compatibility rule |
| --- | --- |
| Core public API | Rust source compatibility is not yet guaranteed; trait additions are breaking changes for implementors. |
| Backend implementation API | Constructors and backend-specific configuration may change independently of Core unless explicitly documented as a Core contract. |
| Guest protocol | Versioned at runtime; an incompatible peer must be rejected rather than guessed. |
| Worker protocol | Versioned and authenticated; request IDs, bounds, and replay rules are protocol behavior. |
| Snapshot format | Versioned independently of Core and runtime APIs; manifests carry format and integrity metadata. |
| Image manifest | Versioned independently of the image resolver implementation. |

A patch release should not silently change persisted snapshot or image formats. A minor release may add non-breaking Core conveniences, but adding a required trait method is breaking for extension authors and therefore requires a pre-1.0 version bump. Backend crates must not expose SQLx, Firecracker, Linux, or AWS types through Core trait signatures.
