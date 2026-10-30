"""Separately authored reference check for the local read-only worker result.

Double hashing is a useful functional cross-check, not an independent human
review, process isolation, malicious-worker attestation, or production QA.
"""

import hashlib
from pathlib import Path


def verify_file_independently(path: Path, proposed_hash: str,
                              proposed_size: int, max_bytes: int) -> bool:
    if not isinstance(proposed_hash, str) or len(proposed_hash) != 64:
        return False
    if type(proposed_size) is not int or proposed_size < 0 or proposed_size > max_bytes:
        return False
    try:
        with path.open("rb") as file:
            data = file.read(max_bytes + 1)
    except OSError:
        return False
    return (
        len(data) == proposed_size
        and len(data) <= max_bytes
        and hashlib.sha256(data).hexdigest() == proposed_hash
    )
