"""Ed25519-gated HANTER *sandbox reference* for a local read-only worker.

Key pairs in tests are ephemeral. Trust anchors and revocation snapshots are
injected as trusted local fixtures, NOT a deployed AI Passport, Guardian Core
service, Approval Gateway, HSM, or independently maintained revocation service.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .pilot import ACTION, Denied, canonical, execute_demo, issue_demo_permit

DOMAIN = b"IMPERIAL_CORE_HANTER_OFFLINE_PASSPORT_V2\n"
AUDIENCE = "hanter-offline-nca-worker"
MAX_TTL = 300
MAX_REVOCATION_AGE = 60
ROLE_NAMES = ("passport", "guardian", "approval")

PASSPORT_FIELDS = frozenset({
    "version", "kind", "iss", "kid", "jti", "aud",
    "tenant", "orchestrator", "agent", "job_id", "path",
    "action", "skills", "cost_cents", "external_effects",
    "issued_at", "not_before", "expires_at",
})
DECISION_FIELDS = frozenset({
    "version", "kind", "iss", "kid", "jti", "decision",
    "passport_sha256", "issued_at", "not_before", "expires_at",
})


@dataclass(frozen=True)
class TrustConfig:
    """Local public verification keys: role -> key ID -> (issuer, public key)."""

    keys: dict[str, dict[str, tuple[str, Ed25519PublicKey]]]


@dataclass(frozen=True)
class RevocationSnapshot:
    """Caller-provided local test state; this is NOT a trusted external feed."""

    as_of: int
    revoked_ids: frozenset[str] = frozenset()
    disabled_issuers: frozenset[str] = frozenset()
    kill_switch: bool = False


def sign_demo_document(payload: dict, private_key: Ed25519PrivateKey) -> dict:
    """Sign ONLY synthetic test data using freshly generated keys."""
    signature = private_key.sign(DOMAIN + canonical(payload))
    return {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def _text(value: object, *, max_length: int = 128) -> bool:
    return (type(value) is str and 0 < len(value) <= max_length
            and value.isascii() and all(32 < ord(c) < 127 for c in value))


def _check_schema(payload: dict, kind: str, now: int) -> None:
    expected = PASSPORT_FIELDS if kind == "passport" else DECISION_FIELDS
    if set(payload) != expected or payload.get("kind") != kind:
        raise Denied("BAD_DOCUMENT_SCHEMA")
    if type(payload["version"]) is not int or payload["version"] != 2:
        raise Denied("BAD_DOCUMENT_SCHEMA")
    for name in ("iss", "kid", "jti"):
        if not _text(payload[name]):
            raise Denied("BAD_DOCUMENT_SCHEMA")
    for name in ("issued_at", "not_before", "expires_at"):
        if type(payload[name]) is not int:
            raise Denied("BAD_DOCUMENT_SCHEMA")
    if not (now - MAX_TTL <= payload["issued_at"] <= now + 30
            and payload["issued_at"] <= payload["not_before"] <= now
            and now < payload["expires_at"]
            and 0 < payload["expires_at"] - payload["issued_at"] <= MAX_TTL):
        raise Denied("INVALID_DOCUMENT_TIME")
    if kind == "passport":
        for name in ("aud", "tenant", "orchestrator", "agent", "job_id", "path", "action"):
            if not _text(payload[name]):
                raise Denied("BAD_DOCUMENT_SCHEMA")
        if (type(payload["skills"]) is not list
                or payload["action"] not in (ACTION, "LLM_PROPOSAL")
                or payload["skills"] != [payload["action"]]
                or type(payload["cost_cents"]) is not int
                or type(payload["external_effects"]) is not bool):
            raise Denied("BAD_DOCUMENT_SCHEMA")
    else:
        if (payload["decision"] != "ALLOW"
                or not isinstance(payload["passport_sha256"], str)
                or len(payload["passport_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in payload["passport_sha256"])):
            raise Denied("POLICY_HOLD")


def _verify(document: dict, *, kind: str, trust: TrustConfig,
            revocations: RevocationSnapshot, now: int) -> dict:
    if type(document) is not dict or set(document) != {"payload", "signature"}:
        raise Denied("BAD_DOCUMENT")
    payload, signature = document["payload"], document["signature"]
    if type(payload) is not dict or type(signature) is not str:
        raise Denied("BAD_DOCUMENT")
    if kind not in ROLE_NAMES:
        raise Denied("BAD_ROLE")
    _check_schema(payload, kind, now)
    if payload["jti"] in revocations.revoked_ids:
        raise Denied("REVOKED_DOCUMENT")
    if payload["iss"] in revocations.disabled_issuers:
        raise Denied("DISABLED_ISSUER")
    entry = trust.keys.get(kind, {}).get(payload["kid"])
    if not entry or payload["iss"] != entry[0]:
        raise Denied("UNTRUSTED_ISSUER")
    try:
        raw = base64.b64decode(signature + "=" * (-len(signature) % 4),
                               altchars=b"-_", validate=True)
        if len(raw) != 64:
            raise ValueError("signature must be exactly 64 bytes")
        entry[1].verify(raw, DOMAIN + canonical(payload))
    except (InvalidSignature, ValueError, TypeError, OverflowError):
        raise Denied("INVALID_SIGNATURE") from None
    return payload


def execute_signed_demo(
    passport: dict,
    guardian_decision: dict,
    approval_decision: dict,
    *,
    trust: TrustConfig,
    revocations: RevocationSnapshot,
    secret: bytes,
    routes: set[tuple[str, str, str]],
    workspace: Path,
    ledger_path: Path,
    now: int,
) -> dict:
    """Signed, role-separated gate on the existing offline read-only task."""
    if (type(now) is not int or type(revocations.as_of) is not int
            or type(revocations.kill_switch) is not bool
            or not isinstance(revocations.revoked_ids, frozenset)
            or not isinstance(revocations.disabled_issuers, frozenset)
            or revocations.as_of > now
            or now - revocations.as_of > MAX_REVOCATION_AGE):
        raise Denied("STALE_OR_BAD_REVOCATION_STATE")
    if revocations.kill_switch:
        raise Denied("OWNER_KILL_SWITCH")

    p = _verify(passport, kind="passport", trust=trust,
                revocations=revocations, now=now)
    if p["aud"] != AUDIENCE:
        raise Denied("WRONG_AUDIENCE")
    if (p["tenant"], p["orchestrator"], p["agent"]) not in routes:
        raise Denied("UNROUTABLE")
    if p["action"] != ACTION or p["cost_cents"] != 0 or p["external_effects"]:
        raise Denied("POLICY_HOLD")

    fingerprint = hashlib.sha256(DOMAIN + canonical(p)).hexdigest()
    g = _verify(guardian_decision, kind="guardian", trust=trust,
                revocations=revocations, now=now)
    a = _verify(approval_decision, kind="approval", trust=trust,
                revocations=revocations, now=now)
    if g["passport_sha256"] != fingerprint or a["passport_sha256"] != fingerprint:
        raise Denied("DECISION_TASK_MISMATCH")
    # The underlying v1 demo worker still uses HMAC; this is not a remotely
    # authenticated or externally deployed production execution channel.
    local_permit = issue_demo_permit(
        secret, tenant=p["tenant"], orchestrator=p["orchestrator"],
        agent=p["agent"], job_id=p["job_id"], path=p["path"],
        now=now, ttl=min(120, p["expires_at"] - now),
    )
    result = execute_demo(
        local_permit, secret=secret, routes=routes,
        workspace=workspace, ledger_path=ledger_path, now=now,
    )
    result["passport"] = "ED25519_DEMO_VERIFIED"
    result["guardian"] = "SIGNED_DEMO_ALLOW"
    result["approval_gateway"] = "SIGNED_DEMO_ALLOW"
    result["production_authorized"] = False
    return result
