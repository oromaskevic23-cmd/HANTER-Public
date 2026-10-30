"""HANTER federated handoff: *offline, non-production reference pilot*.

This is real local read-only work, not an AI model or safe code-execution sandbox.
HMAC permits are demo-specific, NOT production AI Passports or Owner approvals.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
import time
from pathlib import Path, PurePosixPath

from .qa import verify_file_independently

MAX_FILE_BYTES = 1_048_576
MAX_PERMIT_SECONDS = 300
ACTION = "SHA256_FILE"
FIELDS = frozenset({
    "version", "tenant", "orchestrator", "agent", "job_id",
    "path", "action", "issued_at", "expires_at",
    "cost_cents", "external_effects",
})


class Denied(Exception):
    """A fail-closed decision. The error code is intended for local QA only."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def issue_demo_permit(secret: bytes, *, tenant: str, orchestrator: str,
                      agent: str, job_id: str, path: str,
                      now: int, action: str = ACTION,
                      cost_cents: int = 0, external_effects: bool = False,
                      ttl: int = 120) -> dict:
    """Issue only a locally testable MAC, not an AI Passport."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("demo HMAC key must have at least 32 bytes")
    payload = dict(
        version=1, tenant=tenant, orchestrator=orchestrator,
        agent=agent, job_id=job_id, path=path, action=action,
        issued_at=now, expires_at=now + ttl,
        cost_cents=cost_cents, external_effects=external_effects,
    )
    return {
        "payload": payload,
        "mac": hmac.new(secret, canonical(payload), hashlib.sha256).hexdigest(),
    }


def _validate(permit: dict, secret: bytes, routes: set[tuple[str, str, str]], now: int) -> dict:
    if not isinstance(permit, dict) or set(permit) != {"payload", "mac"}:
        raise Denied("BAD_PERMIT")
    payload, mac = permit["payload"], permit["mac"]
    if not isinstance(payload, dict) or set(payload) != FIELDS:
        raise Denied("BAD_SCHEMA")
    if not isinstance(mac, str) or len(mac) != 64:
        raise Denied("BAD_SIGNATURE")
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise Denied("BAD_TRUST_KEY")
    try:
        digest = hmac.new(secret, canonical(payload), hashlib.sha256).hexdigest()
    except (TypeError, ValueError, OverflowError):
        raise Denied("BAD_SCHEMA") from None
    if not hmac.compare_digest(digest, mac):
        raise Denied("BAD_SIGNATURE")
    for field in ("tenant", "orchestrator", "agent", "job_id", "path", "action"):
        val = payload[field]
        if not isinstance(val, str) or not val or len(val) > 128:
            raise Denied("BAD_SCHEMA")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise Denied("BAD_SCHEMA")
    for field in ("issued_at", "expires_at", "cost_cents"):
        if type(payload[field]) is not int:
            raise Denied("BAD_SCHEMA")
    if type(payload["external_effects"]) is not bool:
        raise Denied("BAD_SCHEMA")
    if (payload["issued_at"] > now + 30
            or payload["expires_at"] <= now
            or payload["expires_at"] <= payload["issued_at"]
            or payload["expires_at"] - payload["issued_at"] > MAX_PERMIT_SECONDS):
        raise Denied("EXPIRED_OR_INVALID_TTL")
    if (payload["tenant"], payload["orchestrator"], payload["agent"]) not in routes:
        raise Denied("UNROUTABLE")
    if payload["action"] != ACTION or payload["cost_cents"] != 0 or payload["external_effects"]:
        raise Denied("POLICY_HOLD")
    return payload


def _resolve_file(workspace: Path, tenant: str, raw_path: str) -> Path:
    """Reject traversals and links. This is NOT a hardened filesystem sandbox."""
    path = PurePosixPath(raw_path)
    if (path.is_absolute() or "\\" in raw_path or ":" in raw_path
            or any(x in ("", ".", "..") for x in raw_path.split("/"))):
        raise Denied("INVALID_PATH")
    tenant_root = workspace / tenant
    # Tenant names must not become paths.
    if not tenant.replace("-", "").replace("_", "").isalnum():
        raise Denied("INVALID_TENANT")
    current = tenant_root
    if current.is_symlink():
        raise Denied("INVALID_PATH")
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise Denied("INVALID_PATH")
    if not current.resolve().is_relative_to(tenant_root.resolve()):
        raise Denied("INVALID_PATH")
    if not current.is_file():
        raise Denied("FILE_MISSING")
    return current


def _hash_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    try:
        with path.open("rb") as stream:
            while True:
                buf = stream.read(64 * 1024)
                if not buf:
                    break
                n += len(buf)
                if n > MAX_FILE_BYTES:
                    raise Denied("FILE_TOO_LARGE")
                h.update(buf)
    except OSError:
        raise Denied("FILE_READ_FAILED") from None
    return h.hexdigest(), n


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path, timeout=5)
    con.execute("PRAGMA busy_timeout=5000")
    con.execute("""CREATE TABLE IF NOT EXISTS claims (
        tenant TEXT NOT NULL, job_id TEXT NOT NULL,
        state TEXT NOT NULL, PRIMARY KEY (tenant, job_id)
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL,
        job_id TEXT NOT NULL, state TEXT NOT NULL, artifact TEXT NOT NULL,
        previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
    )""")
    con.commit()
    return con


def _append(con: sqlite3.Connection, tenant: str, job: str,
            state: str, artifact: str = "") -> None:
    row = con.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    prev = row[0] if row else "0" * 64
    fields = dict(tenant=tenant, job_id=job, state=state, artifact=artifact)
    entry = hashlib.sha256((prev + "|").encode() + canonical(fields)).hexdigest()
    con.execute(
        "INSERT INTO audit (tenant,job_id,state,artifact,previous_hash,entry_hash) "
        "VALUES (?,?,?,?,?,?)", (tenant, job, state, artifact, prev, entry)
    )


def verify_audit(db_path: Path) -> bool:
    """Detect in-place edits when the chain anchor is trusted separately.

    This local, mutable SQLite table is NOT a tamper-proof or signed Audit Ledger.
    """
    with _connect(db_path) as con:
        prev = "0" * 64
        for seq, tenant, job, state, artifact, recorded_prev, entry in con.execute(
            "SELECT seq,tenant,job_id,state,artifact,previous_hash,entry_hash "
            "FROM audit ORDER BY seq"
        ):
            fields = dict(tenant=tenant, job_id=job, state=state, artifact=artifact)
            expected = hashlib.sha256((prev + "|").encode() + canonical(fields)).hexdigest()
            if not hmac.compare_digest(recorded_prev, prev) or not hmac.compare_digest(entry, expected):
                return False
            prev = entry
        return True


def execute_demo(permit: dict, *, secret: bytes,
                 routes: set[tuple[str, str, str]],
                 workspace: Path, ledger_path: Path, now: int | None = None) -> dict:
    """Bounded read-only execution; never call with customer or private data."""
    if now is None:
        now = int(time.time())
    payload = _validate(permit, secret, routes, now)
    tenant, job = payload["tenant"], payload["job_id"]
    file_path = _resolve_file(workspace, tenant, payload["path"])

    # BEGIN IMMEDIATE serializes the replay check and reservation across processes.
    with _connect(ledger_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            con.execute(
                "INSERT INTO claims (tenant,job_id,state) VALUES (?,?,?)",
                (tenant, job, "RESERVED"),
            )
        except sqlite3.IntegrityError:
            raise Denied("REPLAY") from None
        _append(con, tenant, job, "RESERVED")

    try:
        digest, size = _hash_file(file_path)
        # A separately authored QA path reopens the file and re-hashes it.
        qa = verify_file_independently(file_path, digest, size, MAX_FILE_BYTES)
        if not qa:
            raise Denied("QA_FAILED")
    except Exception:
        with _connect(ledger_path) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE claims SET state='FAILED' WHERE tenant=? AND job_id=?", (tenant, job))
            _append(con, tenant, job, "FAILED")
        raise

    with _connect(ledger_path) as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("UPDATE claims SET state='QA_PASSED' WHERE tenant=? AND job_id=?", (tenant, job))
        _append(con, tenant, job, "QA_PASSED", digest)

    return {
        "tenant": tenant, "job_id": job, "agent": payload["agent"],
        "orchestrator": payload["orchestrator"], "sha256": digest,
        "bytes": size, "qa": "PASS_LOCAL_DOUBLE_HASH",
        "external_effects": 0, "production_authorized": False,
    }


def local_demo() -> dict:
    """A disposable, repeatable functional example without cloud or model access."""
    with tempfile.TemporaryDirectory(prefix="hanter-offline-") as root:
        root_path = Path(root)
        ws = root_path / "workspace"
        (ws / "demo-tenant").mkdir(parents=True)
        (ws / "demo-tenant" / "source.txt").write_text("IMPERIAL Core - bounded local evidence\n")
        key = secrets.token_bytes(32)
        ts = int(time.time())
        permit = issue_demo_permit(
            key, tenant="demo-tenant", orchestrator="orchestrator-engineering",
            agent="NCA-LOCAL-001", job_id="demo-mission-001",
            path="source.txt", now=ts,
        )
        ledger = root_path / "audit.sqlite"
        result = execute_demo(
            permit, secret=key,
            routes={("demo-tenant", "orchestrator-engineering", "NCA-LOCAL-001")},
            workspace=ws, ledger_path=ledger, now=ts,
        )
        result["audit_chain_valid"] = verify_audit(ledger)
        return result


if __name__ == "__main__":
    print(json.dumps(local_demo(), sort_keys=True, indent=2))
