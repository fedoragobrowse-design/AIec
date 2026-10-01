#!/usr/bin/env python3
"""Print a short, verifiable summary of an AIec Firecracker guest artifact.

Used by scripts/firecracker-coding-dogfood.sh before booting a VM so a broken
or non-coding image fails fast with a precise message instead of producing a
confusing clone failure inside the guest.

Usage: guest_artifact_report.py <artifact-dir> [<rootfs> <kernel>]
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REQUIRED_CAPABILITIES = ("git", "ca-certificates")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> None:
    print(f"guest artifact error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if len(sys.argv) < 2:
        fail("usage: guest_artifact_report.py <artifact-dir> [<rootfs> <kernel>]")

    directory = Path(sys.argv[1])
    metadata_path = directory / "guest-capabilities.json"
    if not metadata_path.is_file():
        fail(f"missing {metadata_path}; the image was not built by scripts/build-firecracker-guest.sh")

    try:
        metadata = json.loads(metadata_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"unreadable {metadata_path}: {error}")
        return 1

    for key in ("base", "profile", "capabilities", "rootfs_sha256", "guest_agent_version"):
        if not metadata.get(key):
            fail(f"{metadata_path} is missing required key {key!r}")
    if not isinstance(metadata.get("guest_protocol_version"), int):
        fail(f"{metadata_path} is missing required key 'guest_protocol_version'")
    if metadata["guest_protocol_version"] != REQUIRED_PROTOCOL_VERSION:
        fail(
            f"{metadata_path} records guest protocol "
            f"{metadata['guest_protocol_version']}, this control plane requires "
            f"{REQUIRED_PROTOCOL_VERSION}"
        )

    rootfs = Path(sys.argv[2]) if len(sys.argv) > 2 else directory / metadata.get(
        "rootfs", "aiec-rootfs.ext4"
    )
    if not rootfs.is_file():
        fail(f"missing rootfs image {rootfs}")
    if not rootfs.stat().st_size:
        fail(f"rootfs image {rootfs} is empty")

    actual = sha256_file(rootfs)
    if actual != metadata["rootfs_sha256"]:
        fail(
            f"rootfs digest mismatch for {rootfs}: recorded "
            f"{metadata['rootfs_sha256']}, actual {actual}"
        )

    if metadata.get("kernel_sha256") and len(sys.argv) > 3:
        kernel = Path(sys.argv[3])
        if not kernel.is_file():
            fail(f"missing kernel image {kernel}")
        kernel_actual = sha256_file(kernel)
        if kernel_actual != metadata["kernel_sha256"]:
            fail(
                f"kernel digest mismatch for {kernel}: recorded "
                f"{metadata['kernel_sha256']}, actual {kernel_actual}"
            )

    capabilities = list(metadata["capabilities"])
    missing = [name for name in REQUIRED_CAPABILITIES if name not in capabilities]
    if metadata.get("profile") != "coding" or missing:
        fail(
            "artifact is not coding-capable: "
            f"profile={metadata.get('profile')!r} missing={missing or 'none'}"
        )

    print(f"guest artifact:      {rootfs}")
    print(f"base:                {metadata['base']}")
    print(f"profile:             {metadata['profile']}")
    print(f"artifact version:    {metadata.get('artifact_version', 'unknown')}")
    print(f"guest agent version: {metadata['guest_agent_version']}")
    print(
        f"guest protocol:      {metadata['guest_protocol_version']}"
    )
    print(f"git version:         {metadata.get('git_version', 'unknown')}")
    print(f"capabilities:        {', '.join(capabilities)}")
    print(f"rootfs sha256:       {actual}")
    if metadata.get("built_at"):
        print(f"built at:            {metadata['built_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
