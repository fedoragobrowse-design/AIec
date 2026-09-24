# Images

The MVP allowlists `python:3.13`, `node:24`, `rust:stable`, `ubuntu:24.04`, and `alpine:3.21`. Resolver output is keyed by SHA-256 of the canonical reference (`afimg1_...`), not trusted registry metadata.

Production images are rootfs artifacts built and signed outside the API. Build a minimal ext4 filesystem, install the guest agent, create `/workspace`, enable virtio drivers and vsock, remove package caches, hash the artifact, and publish it to private object storage. Only administrator-approved content hashes may enter the image table.

The development backend maps allowlisted names to the host's installed tools inside a read-only system view. It does not pull arbitrary registries. Add a registry only with digest pinning, signature verification, malware policy, size/decompression limits, and cache isolation.
