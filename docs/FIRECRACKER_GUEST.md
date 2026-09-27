# Firecracker guest image

The Firecracker runtime boots `vmlinux` with the ext4 image produced by `scripts/build-firecracker-guest.sh`. The guest is a Debian userland with a coding toolchain: it runs `git`, `python3`, `curl`, `tar`/`gzip`, and the coreutils a coding agent expects, with a real CA bundle and working DNS.

## Base image and packages

| Item | Value |
| --- | --- |
| Base image | `debian:bookworm-slim` |
| Base digest | `debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251` |
| Installed packages | `git ca-certificates curl python3 tar gzip coreutils util-linux hostname` (`--no-install-recommends`, apt lists and docs stripped afterwards) |
| Guest agent | `aiec-guest` 0.1.0, static musl, at `/usr/local/bin/aiec-guest` |

Versions measured inside the built container (not hardcoded):

| Tool | Version |
| --- | --- |
| git | `git version 2.39.5` (Debian `1:2.39.5-0+deb12u3`) |
| curl | `curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.22` |
| python3 | `Python 3.11.2` |
| tar | `tar (GNU tar) 1.34` |

The base image is pinned by tag and the resolved repo digest is recorded in `guest-capabilities.json`; `AIEC_GUEST_BASE_IMAGE` overrides the tag for a controlled upgrade, and the digest in the recorded capabilities file is what identifies the result.

## Artifact layout

`.aiec/images/` (the default output directory) contains:

| File | Contents |
| --- | --- |
| `aiec-rootfs.ext4` | 4 GiB ext4 image; ~282 MiB of Debian bookworm-slim userland with the guest agent and the baked guest secret |
| `vmlinux` | uncompressed kernel (provided separately, not produced by this script) |
| `guest-capabilities.json` | machine-readable description of the artifact (see below) |
| `SHA256SUMS` | `sha256sum` lines for the rootfs and the kernel |
| `manifest.json` | runtime boot contract: rootfs name, kernel name, `control_port: 1024`, `guest_cid: 3` |

Inside the image:

- `/init` is a symlink to `/sbin/init`; `/sbin/init` is the repository-owned `guest/rootfs/sbin/init` (POSIX `sh`, no BusyBox applets). It mounts `/proc`, `/sys`, `devtmpfs` on `/dev`, `devpts`, `tmpfs` on `/run`, sets the hostname, checks `/etc/aiec-guest-secret`, exports `AIEC_GUEST_SECRET`, and supervises the guest agent in a restart loop. The agent listens on vsock port 1024 and serves `/workspace`, which init guarantees exists.
- `/etc/aiec-guest-secret` holds the build-time secret with mode 0600.
- `/etc/resolv.conf` is a real file with `nameserver 1.1.1.1` and `nameserver 8.8.8.8` (the docker-managed bind mount is never written through).
- Debian bookworm is merged-usr, so `/bin`, `/sbin` and `/lib` are symlinks into `/usr`; the guest agent and the repository skeleton are installed through them.

## Rebuilding

```bash
AIEC_GUEST_SECRET=$(openssl rand -hex 32) bash scripts/build-firecracker-guest.sh
```

| Input | Meaning |
| --- | --- |
| `AIEC_GUEST_SECRET` | required, at least 32 bytes, baked into the image; rotate it and rebuild to change it |
| `AIEC_KERNEL` | kernel to hash and describe, default `.aiec/images/vmlinux` |
| `AIEC_GUEST_BASE_IMAGE` | base image, default `debian:bookworm-slim` |
| `AIEC_GUEST_ROOTFS_SIZE` | image size, default `4G` |
| positional argument 1 | output directory, default `.aiec/images` |

Requirements: docker, the Rust toolchain with the `x86_64-unknown-linux-musl` target, and `e2fsprogs` (`mke2fs`, `e2fsck`, `resize2fs`, `debugfs`). The build needs the network to pull the base image and run `apt-get`. When the build user cannot reach the docker socket directly, every docker call is routed through `sg docker -c '...'`; the script fails with a clear error if neither path works.

Exit codes: `0` on success, `1` on a build error, `2` when the rootfs was built but `AIEC_KERNEL` does not exist (in that case `guest-capabilities.json` is written with `"kernel_sha256": null` and `SHA256SUMS`/`manifest.json` are not rewritten).

The image is verified offline without booting it:

```bash
debugfs -R 'stat /usr/bin/git' .aiec/images/aiec-rootfs.ext4
debugfs -R 'cat /etc/resolv.conf' .aiec/images/aiec-rootfs.ext4
```

## Capability profile

`guest-capabilities.json` describes what a sandbox built on this image can do:

```json
{"schema":1,"artifact_version":"1.0.0","base":"<base image digest>","profile":"coding",
 "capabilities":["sh","coreutils","git","ca-certificates","dns","https","tar","gzip","curl","python3"],
 "git_version":"<measured>","guest_agent_version":"<Cargo version>","rootfs_sha256":"<sha256>",
 "kernel_sha256":"<sha256>|null","built_at":"<RFC3339 UTC>"}
```

- `profile: "coding"` marks the image as a coding-capable guest rather than a minimal shell.
- `capabilities` are stable identifiers, not versions: `sh`, `coreutils`, `git`, `ca-certificates`, `dns`, `https`, `tar`, `gzip`, `curl`, `python3`.
- `git_version` and `guest_agent_version` are the measured `git --version` output and the `aiec-guest` crate version from the workspace manifest.
- `rootfs_sha256` covers `aiec-rootfs.ext4` as written by the script; `kernel_sha256` covers the kernel and is `null` when the build had none.

The runtime consumes this file through `aiec-runtime`'s `guest_artifact` module (`load_guest_artifact`/`verify_guest_artifact`): it fails closed when the file is missing, when the rootfs is unreadable, or when the recorded `rootfs_sha256` does not match the image on disk, and it verifies `kernel_sha256` whenever it is present. `profile == "coding"` together with `git` in `capabilities` is what marks the artifact as coding-capable; a stricter deployment can additionally require `ca-certificates`. `schema` and `built_at` are informational.

## Networking

The guest does not configure its own address. The runtime network attachment supplies the guest addresses: `NetworkAttachment::guest_addresses` becomes the `ip=` autoconfiguration parameters on the Firecracker boot cmdline, and the kernel applies them to the virtio-net interface (`CONFIG_IP_PNP` and `CONFIG_VIRTIO_NET` in the approved `vmlinux`). The guest userland has no role in address assignment. The guest's only DNS responsibility is to ship a usable `/etc/resolv.conf`, which the build writes as a plain file with the public resolvers `1.1.1.1` and `8.8.8.8`. The control channel is vsock (guest CID 3, port 1024) and is unaffected by IP autoconfiguration.
