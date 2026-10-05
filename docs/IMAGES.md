# Images

The MVP allowlists `python:3.13`, `node:24`, `rust:stable`, `ubuntu:24.04`, and `alpine:3.21`. Resolver output is keyed by SHA-256 of the canonical reference (`afimg1_...`), not trusted registry metadata.

Production images are rootfs artifacts built and signed outside the API. Build a minimal ext4 filesystem, install the guest agent, create `/workspace`, enable virtio drivers and vsock, remove package caches, hash the artifact, and publish it to private object storage. Only administrator-approved content hashes may enter the image table.

The development backend maps allowlisted names to the host's installed tools inside a read-only system view. It does not pull arbitrary registries. Add a registry only with digest pinning, signature verification, malware policy, size/decompression limits, and cache isolation.

Production `aiec-server` now requires `AIEC_IMAGE_MANIFEST` and `AIEC_IMAGE_MANIFEST_SECRET`, requires a signing secret of at least 32 bytes, verifies the manifest HMAC, verifies the rootfs SHA-256 before resolving, and fails closed on reference or digest mismatch. The manifest deployment schema and external key-rotation process remain operator-controlled and are not yet independently audited. The development `StandardImageResolver` remains allowlist-only and unsigned.

## Per-sandbox root filesystem materialization

Each Firecracker sandbox gets its own writable disk image derived from the
immutable base image. The runtime asks the filesystem to clone the base
copy-on-write with the `FICLONE` ioctl, so the base's blocks are shared and
only the blocks the guest writes are copied. Reflink support is a property of
the kernel and the filesystem rather than an assumption, so the capability is
probed on every materialization. When the kernel reports that cloning is not
possible, the runtime falls back to a full byte copy. The recognized
"cannot clone" answers are the same set `cp --reflink=always` uses: `EOPNOTSUPP`,
`ENOTTY`, `ENOSYS`, `EXDEV`, `EINVAL`, and `ETXTBSY`. Any other error — a full
disk, an I/O failure, a permission problem — is reported as a failure and is
never retried as a full copy, which would hide it.

The invariants, which do not depend on which path ran:

- The base image is never hard-linked and never opened for writing. A hard
  link would give the guest a second writer on the image every other sandbox
  starts from.
- Two sandboxes materialized from the same base never share a writable file,
  so a write in sandbox A is invisible to sandbox B and to the base.
- The destination is created exclusively. An existing path is an error, not a
  truncate, so a stale or foreign image is never destroyed and never silently
  reused as this sandbox's disk.
- A materialization that fails leaves no partial image behind.
- The materialized image keeps the base's permission bits and always keeps
  owner read and write, because the runtime rewrites the image locally when a
  sandbox requests a different disk size.

The 120-second bound still covers the whole materialization, but what expiry
means has changed. The materialization is a cancellable future: when the bound
expires, the runtime drops that future, and the drop is the cancellation signal.
The copy observes it at the next chunk boundary — the full-copy fallback moves
the image through a fixed 4 MiB buffer rather than a negotiated one — and every
exit that is not a complete image removes the destination it created. A create
that timed out therefore leaves no background copy filling a disk nobody is
going to boot, and no writable image reappearing after cleanup removed the
directory. What cancellation cannot do is interrupt a `write` that is already in
the kernel, so the stop is bounded by one chunk of I/O, not by a deadline; and
the bound is unmeasured, because the number depends on the storage, not on the
code. A hard kill (`SIGKILL`) is the case nothing cleans up, because the
process that would have removed the file is gone.

The `e2fsck`/`resize2fs` shrink and grow steps are unchanged. The
`rootfs_copy_done` log line records a `method` field of `reflink` or `copy`
alongside `bytes` and `elapsed_ms`; that field is what to compare when
measuring how often a deployment actually gets copy-on-write.

The base image and the state directory are separate paths, and both matter. A
deployment gets the cheaper path only when `AIEC_ROOTFS` and `AIEC_STATE_DIR`
are on the *same* reflink-capable filesystem: across filesystems the clone is
answered `EXDEV` and every sandbox silently pays the full copy. On a filesystem
without reflink support at all (ext4 and tmpfs among them) the copy is used the
same way. Either case logs `method="copy"`, so that field is the check: AIec
does not assume support and will not misreport a copy as a clone.

Because the destination is created exclusively, a create that died without
running its cleanup — a `SIGKILL` mid-materialization — leaves a short
`rootfs.ext4` behind, and re-driving `create` for the same sandbox then fails
with an error naming that path instead of truncating and booting a half-written
disk. Recovery is to remove the stale file yourself and create again.
Reconciliation is not that mechanism: `reconcile_local` only *reports* VM
directories whose API socket is missing, for operator review, and never removes
anything. Destroying the sandbox removes its whole VM directory, so the
ordinary create/destroy cycle leaves nothing stale; this only affects a create
re-driven for an identifier that already has a directory, which nothing in the
current request paths does.

### Verified deployment behavior

`benchmarks/runtime-rootfs-docker-live-2026-09-30.json` records an integrated
Firecracker create/first-exec/destroy cycle with a 4 GiB base: the actual
`rootfs_copy_done` log reports `method="reflink"` and `elapsed_ms=238`.
The base's inode, timestamps and size were unchanged; destroy removed the new
VM process and socket directory and released its database lease.

The same record contains 40 Auto materializations on btrfs (40 reflinks), 40
on native tmpfs after an explicit unsupported-ioctl probe (40 byte copies),
and 40 across filesystems (40 byte copies). Every materialization checked
distinct inodes and base/A/B write isolation, and left no scratch image.
Those microbenchmarks used a 2 MiB guest-generated fixture and a stripped debug
binary; they establish correctness and fallback behavior, not a release-build
or 4 GiB throughput ratio.

Artifact collection over the same protocol runs in bounded 64 KiB groups rather
than one read per chunk, because a worker-backed read is a network round trip
plus two ownership checks. Measured on a production host: collecting 16.8 MiB took
129 360 ms with one chunk per read and 8 945 ms grouped, with every served byte
hashing to the digest recorded at collection. The authorization that gates
publication is unchanged — a lease replaced during a group still stops every
byte of it — because the group is read between the two checks and buffered
until the second one passes.

## Guest image verification

A worker verifies the configured guest image before it boots a guest, because
hashing a multi-gigabyte rootfs on the request path would blow the control
plane's client timeout. The verdict is cached so that cost is paid once rather
than once per sandbox, and the cache is bounded on every axis a long-lived
process can grow on:

- **Identity.** A verdict is keyed on the complete identity of everything the
  check reads: for the rootfs, the kernel and the `guest-capabilities.json`
  document, the path, size, inode, device, and the nanosecond modification and
  status-change times. The nanoseconds are load-bearing — `Metadata::mtime` is
  whole seconds, so a rootfs rewritten in place to the same length inside the
  same second used to keep the verdict recorded for the bytes it replaced. The
  manifest document is part of the key because the digest is compared against
  the file on disk, not against the copy the worker loaded at startup.
- **Entries and bytes.** At most 8 identities are remembered, accounting for at
  most 8 GiB of image. Eviction is oldest-verification-first with the key as
  the tie-break, so the entry a bound gives up is deterministic rather than
  whichever one the map happened to yield. An image larger than the whole byte
  bound is verified on every call rather than evicting everything else.
- **Time to live.** A success is trusted for one hour and a failure for one
  minute. The failure TTL is short on purpose: a failure stays visible (a cached
  success is never handed out for a broken image) but a repaired worker is not
  told "still broken" forever, and a new artifact is a new identity, so no
  verdict here can be applied to bytes nobody verified.
- **Concurrency.** At most two images are hashed at a time, and only one
  verification runs per identity: a restart storm would otherwise read the same
  multi-gigabyte file several times over, on the disk the guests are about to
  share with the worker.

What the identity cannot see is a rewrite that preserves size, inode, device and
every timestamp, which means writing over the image's own blocks without letting
the filesystem record it. Re-hashing on every create is the only defence against
that, and paying it per create is the cost the cache exists to avoid. Snapshot
and restore hash the snapshot disk through the same kind of fixed-size streaming
buffer (`guest_artifact.rs` already streamed the guest image), so recording or
checking a snapshot checksum no longer allocates an image-sized buffer.

### Control-plane manifest verification

The worker cache above is not the only place a rootfs digest is checked. The
control plane resolves a Firecracker sandbox's image through
`SignedImageResolver`, and that resolution used to re-read and re-hash the whole
rootfs on every matching request — a 4 GiB read per sandbox create, on the API
process itself. It now keeps one verified digest, shared by every clone of the
resolver:

- **One entry, keyed on the file.** A resolver is configured with a single
  rootfs, so a map would grow with the process rather than with the work. The
  key is the path plus device, inode, length and nanosecond modification and
  status-change times, and the verdict also records which manifest digest it
  was checked against, so a verdict for one manifest can never be read back for
  another.
- **Checked three times.** A hash only answers "are these the signed bytes" if
  the bytes it read were there for the whole read: the identity is compared
  against the opened handle before reading (a path swapped between check and
  open), against the handle after reading (a file written mid-hash), and
  against the path again (a rename or swap behind the handle). Any instability
  is `unavailable` and caches nothing.
- **Single-flight.** Concurrent resolutions of the same image share one hash
  rather than each reading the same file; a caller arriving mid-verification
  waits for that verdict. A cancelled or unwound verification releases the slot
  and remembers nothing.
- **What was not removed.** The manifest HMAC is still verified — once, when the
  resolver is constructed, where the manifest is immutable owned data.
  Re-deriving it on every resolve re-proved a fact that cannot change.
  The digest comparison itself is unchanged, and only a digest actually
  computed from the file, or one whose file identity provably still matches, is
  ever returned. The signing secret is no longer retained for the process
  lifetime, and `Debug` does not carry it.
