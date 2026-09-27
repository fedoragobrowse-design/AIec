# Snapshots

Production snapshots are Firecracker full snapshots, not workspace copies:

1. The guest agent flushes `/workspace`.
2. The worker pauses the VM.
3. Firecracker writes full guest memory and VM/device state.
4. The worker copies and SHA-256-checksums the ext4 disk.
5. The worker resumes the original VM.
6. PostgreSQL records snapshot ownership, key, size, kind, checksum, and completeness after durable object storage succeeds.

Restore creates a new sandbox assignment, verifies the disk checksum, restores the original disk path encoded by the compatible Firecracker version, loads the memory/device snapshot, overrides the new process's vsock UDS, and resumes the original guest workload. The repository contains a Firecracker integration test covering this path, but the current authoritative run is blocked before boot because Firecracker artifacts are not configured; the prior run is historical evidence only.

Firecracker v1.17 does not yet expose a merged block-device path override. Consequently, restore is worker-local and must use a compatible Firecracker build and original filesystem layout. S3 durability does not imply cross-host portability. Keep snapshot memory/state/disk objects together and never restore to an untrusted object.

Portable recovery boundary: `SnapshotKind::Workspace` is the safe cross-instance/cross-worker candidate. The development Bubblewrap workspace snapshot has been exercised by restoring into a distinct sandbox and reading the preserved file. `SnapshotKind::VirtualMachine` and `SnapshotKind::Memory` remain worker-local Firecracker recovery artifacts until compatible host/device-path portability is proven; do not present them as portable workspace snapshots.

A snapshot is incomplete if any component upload or checksum fails. Metadata must not be committed as complete before all required objects are durable. Delete operations remove tenant-authorized object keys and metadata; production should enable bucket versioning, encryption, malware scanning, legal-retention handling, and reconciliation for object-success/database-failure ordering.
