"""HANTER co-signs an Owner-authorized local node stop, for lab use only.

Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
Trust roots and the HANTER test signing key are supplied by the local host.
No key enrollment, network channel or production authority is provided.
"""
from __future__ import annotations

import base64
import hmac
import json
import math
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .pilot import Denied, canonical

OWNER_DOMAIN = b"IMPERIAL_LOCAL_NODE_OWNER_STOP_V1\n"
HANTER_DOMAIN = b"IMPERIAL_LOCAL_NODE_HANTER_STOP_V1\n"
FIELDS = frozenset(("schema", "action", "scope", "node_id", "tenant_id",
                    "orchestrator_id", "worker_id", "reason", "nonce",
                    "issued_at", "expires_at"))
IDENT = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{2,79}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
MAX_TTL = 60


def _clock(clock):
    try:
        value = clock()
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid clock")
        return int(value)
    except Exception:
        raise Denied("STOP_CLOCK_INVALID") from None


def _check_time(payload, now):
    if (type(payload["issued_at"]) is not int or type(payload["expires_at"]) is not int
            or payload["issued_at"] > now or payload["expires_at"] <= now
            or not 0 < payload["expires_at"] - payload["issued_at"] <= MAX_TTL):
        raise Denied("STOP_EXPIRED")


def _check_revocation(revoked):
    try:
        state = revoked()
    except Exception:
        raise Denied("STOP_REVOCATION_UNAVAILABLE") from None
    if type(state) is not bool:
        raise Denied("STOP_REVOCATION_UNAVAILABLE")
    if state:
        raise Denied("STOP_ISSUER_REVOKED")


def cosign_owner_local_stop(payload, owner_signature, *, owner_public_key,
                            hanter_private_key, routes, revoked, clock=time.time):
    """Bind an Owner signature to one allowlisted local NCA node and co-sign.

    This returns a detached envelope only; it does not dispatch to a host.
    Revocation, routes and keys are trusted local configuration, not claims
    supplied by the caller. A real Owner signature must originate externally.
    """
    if (not isinstance(owner_public_key, Ed25519PublicKey)
            or not isinstance(hanter_private_key, Ed25519PrivateKey)):
        raise Denied("STOP_TRUST_KEYS_REQUIRED")
    if hmac.compare_digest(owner_public_key.public_bytes_raw(),
                           hanter_private_key.public_key().public_bytes_raw()):
        raise Denied("SEPARATE_TRUST_ROOTS_REQUIRED")
    if not callable(clock) or not callable(revoked) or not isinstance(routes, (set, frozenset)):
        raise Denied("STOP_TRUST_CONFIGURATION_INVALID")
    if type(payload) is not dict or set(payload) != FIELDS:
        raise Denied("STOP_SCHEMA_DENIED")
    try:
        raw = canonical(payload)
        if len(raw) > 4096:
            raise ValueError("oversized")
        p = json.loads(raw)
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise Denied("STOP_SCHEMA_DENIED") from None
    if (p["schema"] != "imperial.nca.local-stop.v1" or p["action"] != "STOP"
            or p["scope"] != "LOCAL_NODE"):
        raise Denied("STOP_SCOPE_DENIED")
    names = ("node_id", "tenant_id", "orchestrator_id", "worker_id")
    if any(type(p[x]) is not str or not IDENT.fullmatch(p[x]) for x in names):
        raise Denied("STOP_SCHEMA_DENIED")
    if tuple(p[x] for x in names) not in routes:
        raise Denied("STOP_ROUTE_DENIED")
    if (type(p["reason"]) is not str or not 4 <= len(p["reason"]) <= 180
            or not p["reason"].isprintable() or type(p["nonce"]) is not str
            or not NONCE.fullmatch(p["nonce"])):
        raise Denied("STOP_SCHEMA_DENIED")
    first_time = _clock(clock)
    _check_time(p, first_time)
    _check_revocation(revoked)
    if type(owner_signature) is not str or not SIGNATURE.fullmatch(owner_signature):
        raise Denied("STOP_OWNER_SIGNATURE_INVALID")
    try:
        signature = base64.b64decode(owner_signature + "==", altchars=b"-_", validate=True)
        if len(signature) != 64 or base64.urlsafe_b64encode(signature).decode().rstrip("=") != owner_signature:
            raise ValueError("noncanonical signature")
        owner_public_key.verify(signature, OWNER_DOMAIN + raw)
    except (InvalidSignature, TypeError, ValueError):
        raise Denied("STOP_OWNER_SIGNATURE_INVALID") from None
    checked_time = _clock(clock)
    if checked_time < first_time:
        raise Denied("STOP_CLOCK_MOVED_BACKWARDS")
    _check_time(p, checked_time)
    _check_revocation(revoked)
    signed = hanter_private_key.sign(HANTER_DOMAIN + raw)
    return {"payload": p, "owner_signature": owner_signature,
            "hanter_signature": base64.urlsafe_b64encode(signed).decode().rstrip("=")}
