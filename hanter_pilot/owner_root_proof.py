"""Fail-closed, OFFLINE Owner Ed25519 proof-of-possession admission.

Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
This verifier cannot create an Owner identity or authorize a worker.
The public trust root MUST be pinned by a separate trusted Owner-controlled
provisioning process; do not derive it from user input or from this repository.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .pilot import canonical, Denied

DOMAIN = b"IMPERIAL_HANTER_OWNER_ROOT_PROOF_V1\n"
SCHEMA = "imperial.hanter.owner-root-proof.v1"
PURPOSE = "VERIFY_PINNED_OWNER_KEY_POSSESSION_ONLY"
FIELDS = frozenset({
    "schema", "purpose", "tenant_id", "key_id", "nonce_hex", "issued_at",
    "expires_at", "production_authorized", "external_effects", "spending_usd"
})
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,99}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_SECONDS = 300


class OwnerRootProofGate:
    """Verify externally signed challenges with durable anti-replay.

    The trusted public key is never accepted from a claim. SQLite here is an
    offline single-host reference, not a distributed identity or PKI service.
    """

    def __init__(self, db_path: Path, *, pinned_public_key: bytes,
                 key_id: str, tenant_id: str):
        if (type(pinned_public_key) is not bytes or len(pinned_public_key) != 32
                or type(key_id) is not str or not NAME.fullmatch(key_id)
                or type(tenant_id) is not str or not NAME.fullmatch(tenant_id)):
            raise Denied("PINNED_OWNER_TRUST_ROOT_REQUIRED")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_public_key)
        except ValueError as exc:
            raise Denied("PINNED_OWNER_TRUST_ROOT_INVALID") from exc
        self.db_path = Path(db_path)
        if self.db_path.is_symlink() or self.db_path.exists() and not self.db_path.is_file():
            raise Denied("UNSAFE_OWNER_PROOF_DATABASE")
        if not self.db_path.parent.is_dir() or self.db_path.parent.is_symlink():
            raise Denied("INVALID_PROOF_DB_PARENT")
        self.pinned_public_key = pinned_public_key
        self.key_id = key_id
        self.tenant_id = tenant_id
        with self._db() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS challenges (
                nonce_hex TEXT PRIMARY KEY,
                challenge_sha256 TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER
            )""")

    def _db(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=5)
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def issue_challenge(self, *, now: int | None = None) -> dict:
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp < 1:
            raise Denied("CLOCK_INVALID")
        nonce = secrets.token_hex(32)
        payload = {
            "schema": SCHEMA,
            "purpose": PURPOSE,
            "tenant_id": self.tenant_id,
            "key_id": self.key_id,
            "nonce_hex": nonce,
            "issued_at": stamp,
            "expires_at": stamp + MAX_SECONDS,
            "production_authorized": False,
            "external_effects": False,
            "spending_usd": 0,
        }
        digest = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("INSERT INTO challenges VALUES(?,?,?,?,NULL)",
                        (nonce, digest, stamp, stamp + MAX_SECONDS))
        return payload

    def verify(self, payload: object, signature_b64url: object,
               *, now: int | None = None) -> dict:
        stamp = int(time.time()) if now is None else now
        if (type(stamp) is not int or stamp < 1 or type(payload) is not dict
                or set(payload) != FIELDS):
            raise Denied("OWNER_PROOF_SCHEMA_DENIED")
        if (payload["schema"] != SCHEMA or payload["purpose"] != PURPOSE
                or payload["tenant_id"] != self.tenant_id
                or payload["key_id"] != self.key_id
                or type(payload["nonce_hex"]) is not str
                or not HEX64.fullmatch(payload["nonce_hex"])
                or type(payload["issued_at"]) is not int
                or type(payload["expires_at"]) is not int
                or type(payload["production_authorized"]) is not bool
                or payload["production_authorized"] is not False
                or type(payload["external_effects"]) is not bool
                or payload["external_effects"] is not False
                or type(payload["spending_usd"]) is not int
                or payload["spending_usd"] != 0):
            raise Denied("OWNER_PROOF_SCOPE_DENIED")
        if (payload["issued_at"] > stamp or stamp >= payload["expires_at"]
                or payload["expires_at"] - payload["issued_at"] != MAX_SECONDS):
            raise Denied("OWNER_PROOF_EXPIRED")
        if (type(signature_b64url) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature_b64url)):
            raise Denied("OWNER_PROOF_SIGNATURE_INVALID")
        try:
            raw = base64.b64decode(signature_b64url + "==",
                                   altchars=b"-_", validate=True)
            if len(raw) != 64:
                raise ValueError("invalid Ed25519 signature length")
            Ed25519PublicKey.from_public_bytes(self.pinned_public_key).verify(
                raw, DOMAIN + canonical(payload))
        except (InvalidSignature, ValueError, TypeError, OverflowError) as exc:
            raise Denied("OWNER_PROOF_SIGNATURE_INVALID") from exc
        digest = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT challenge_sha256, issued_at, expires_at, consumed_at "
                "FROM challenges WHERE nonce_hex=?", (payload["nonce_hex"],)
            ).fetchone()
            if (row is None or row[3] is not None
                    or not hmac.compare_digest(digest, row[0])
                    or row[1] != payload["issued_at"]
                    or row[2] != payload["expires_at"]):
                raise Denied("UNKNOWN_OR_CONSUMED_OWNER_CHALLENGE")
            updated = con.execute(
                "UPDATE challenges SET consumed_at=? "
                "WHERE nonce_hex=? AND consumed_at IS NULL",
                (stamp, payload["nonce_hex"])
            )
            if updated.rowcount != 1:
                raise Denied("OWNER_CHALLENGE_REPLAY")
        return {
            "schema": "imperial.hanter.owner-root-receipt.v1",
            "stage": "OFFLINE_PINNED_KEY_POSSESSION_VERIFIED",
            "key_id": self.key_id,
            "owner_public_key_sha256": hashlib.sha256(self.pinned_public_key).hexdigest(),
            "challenge_sha256": digest,
            "signature_verified": True,
            "externally_attested_owner_identity": False,
            "revocation_service_verified": False,
            "real_ai_passport_issued": False,
            "independent_qa_verified": False,
            "worker_execution_authorized": False,
            "production_authorized": False,
            "external_effects": False,
            "spending_usd": 0,
        }


def production_preflight(*, owner_identity_attested: object = False,
                         passport_issuer_trusted: object = False,
                         guardian_service_trusted: object = False,
                         approval_service_trusted: object = False,
                         independent_qa_trusted: object = False,
                         sandbox_attested: object = False) -> dict:
    """Inspection only: booleans are never cryptographic authority.

    Even a caller asserting every readiness bit cannot authorize execution.
    """
    return {
        "schema": "imperial.hanter.worker-preflight.v1",
        "requirements_claimed": {
            "owner_identity_attested": owner_identity_attested is True,
            "passport_issuer_trusted": passport_issuer_trusted is True,
            "guardian_service_trusted": guardian_service_trusted is True,
            "approval_service_trusted": approval_service_trusted is True,
            "independent_qa_trusted": independent_qa_trusted is True,
            "sandbox_attested": sandbox_attested is True,
        },
        "actual_signature_envelopes_checked": False,
        "production_authorized": False,
        "worker_start_allowed": False,
        "reason": "EXTERNAL_PRODUCTION_TRUST_AND_LIVE_ENFORCEMENT_MISSING",
    }
