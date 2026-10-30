"""Fail-closed local Docker isolation reference for a single bounded SHA-256 NCA.

Only a pre-existing, locally installed Docker image may be used. Pulling and
assessing the image is out of scope; the container itself has no network access.
This is OS process isolation for synthetic input, not an LLM execution service.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from .pilot import Denied, MAX_FILE_BYTES

IMAGE = "python:3.12-slim"
CONTAINER_SCRIPT = (
    "import hashlib,json,pathlib;"
    "data=pathlib.Path('/input/source').read_bytes();"
    "print(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)},"
    "sort_keys=True))"
)


def isolated_sha256(path: Path, *, image: str = IMAGE, run=subprocess.run) -> dict:
    """Execute a single no-network, read-only container or deny on any error."""
    if not isinstance(path, Path) or path.is_symlink():
        raise Denied("UNSAFE_INPUT_PATH")
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= MAX_FILE_BYTES:
            raise Denied("UNSAFE_INPUT_FILE")
        full_path = path.resolve(strict=True)
    except OSError:
        raise Denied("INPUT_MISSING") from None

    # No host paths other than the explicitly selected input file enter Docker.
    if image != IMAGE:
        raise Denied("UNAPPROVED_IMAGE")

    cmd = [
        "docker", "run", "--rm", "--pull=never",
        "--network=none", "--read-only",
        "--user=65534:65534", "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=32", "--memory=128m",
        "--memory-swap=128m", "--cpus=0.5",
        "--ipc=none",
        "--tmpfs=/tmp:rw,nosuid,noexec,size=8m",
        "--mount", f"type=bind,source={full_path},target=/input/source,readonly",
        "--", image, "python", "-I", "-c", CONTAINER_SCRIPT,
    ]
    try:
        done = run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Denied("ISOLATED_RUNTIME_UNAVAILABLE") from None
    if done.returncode != 0:
        raise Denied("ISOLATED_RUNTIME_FAILED")
    if len(done.stdout) > 2048:
        raise Denied("WORKER_OUTPUT_TOO_LARGE")
    try:
        result = json.loads(done.stdout)
        if set(result) != {"sha256", "bytes"}:
            raise ValueError
        digest = result["sha256"]
        size = result["bytes"]
        if type(size) is not int or type(digest) is not str or len(digest) != 64:
            raise ValueError
        if not all(x in "0123456789abcdef" for x in digest):
            raise ValueError
    except (ValueError, TypeError):
        raise Denied("BAD_WORKER_OUTPUT") from None

    # Separate host-side QA reads the same synthetic input. This cannot prevent
    # concurrent source mutation; use content-addressed snapshots in production.
    with path.open("rb") as f:
        contents = f.read(MAX_FILE_BYTES + 1)
    if len(contents) != size or hashlib.sha256(contents).hexdigest() != digest:
        raise Denied("HOST_QA_MISMATCH")
    return {
        "sha256": digest, "bytes": size,
        "qa": "PASS_HOST_REHASH",
        "network": "none", "filesystem": "read-only",
        "uid": "65534:65534", "external_effects": 0,
        "production_authorized": False,
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hanter-isolated-") as root:
        path = Path(root) / "synthetic.txt"
        path.write_bytes(b"IMPERIAL Core isolated synthetic NCA job\n")
        os.chmod(path, 0o644)  # one harmless synthetic file, readable by container uid 65534
        print(json.dumps(isolated_sha256(path), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
