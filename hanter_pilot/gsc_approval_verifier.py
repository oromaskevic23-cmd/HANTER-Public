"""Pinned Ed25519 Owner + independent QA verification for GSC submit intents.

Founding Architect: Alexander Nikolaevich Romaskevich (RomaskevicH).
Trusted public keys, proof records and revocations MUST originate from separate
Owner-controlled provisioning, not MCP clients or this public repository.
This code never issues keys, signs approvals or submits a sitemap.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"IMPERIAL_GSC_APPROVAL_V1\n"
AUDIENCE = "imperial-gsc-sitemaps-submit"
MAX_AGE = 600
ID = re.compile(r"^[A-Za-z0-9._:-]{3,128}$")
SIG = re.compile(r"^[A-Za-z0-9_-]{86}$")
ROLE = {"owner", "qa"}


class ProofDenied(ValueError):
    """Fails closed with a non-sensitive error code."""


def canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


@dataclass(frozen=True)
class TrustRoot:
    role: str
    issuer: str
    key_id: str
    public_key_raw: bytes

    def validate(self) -> None:
        if (self.role not in ROLE or not isinstance(self.issuer, str)
            or not ID.fullmatch(self.issuer) or not isinstance(self.key_id, str)
            or not ID.fullmatch(self.key_id) or type(self.public_key_raw) is not bytes
            or len(self.public_key_raw) != 32):
            raise ProofDenied("PINNED_TRUST_ROOT_INVALID")
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_raw)
        except ValueError as exc:
            raise ProofDenied("PINNED_TRUST_ROOT_INVALID") from exc


class SignedSubmissionProofs:
    """Separate trusted signers, issuer roles and proof IDs.

    The verifier is a caller-injected trusted-host adapter for SubmissionGate.
    The proof store must originate from authenticated private storage; adding
    self-signed entries to a public git repository confers no authority.
    """

    def __init__(self, *, owner: TrustRoot, qa: TrustRoot,
                 proof_records: dict[str, dict], revoked_ids: frozenset[str],
                 revocations_as_of: int, now: int | None = None):
        owner.validate()
        qa.validate()
        if (owner.role != "owner" or qa.role != "qa"
            or owner.public_key_raw == qa.public_key_raw
            or owner.issuer == qa.issuer or owner.key_id == qa.key_id):
            raise ProofDenied("INDEPENDENT_SIGNERS_REQUIRED")
        if type(now) is not int and now is not None:
            raise ProofDenied("INVALID_CLOCK")
        self.now = int(time.time()) if now is None else now
        if (type(revocations_as_of) is not int
            or revocations_as_of > self.now
            or self.now - revocations_as_of > 60
            or not isinstance(revoked_ids, frozenset)
            or any(type(item) is not str for item in revoked_ids)):
            raise ProofDenied("STALE_REVOCATION_STATE")
        if (type(proof_records) is not dict or len(proof_records) > 1000):
            raise ProofDenied("PROOF_STORE_INVALID")
        self.roots = {"owner": owner, "qa": qa}
        self.proofs = proof_records
        self.revoked = revoked_ids

    def _check(self, role: str, intent: bytes, proof_ref: str) -> bool:
        if (type(role) is not str or role not in self.roots or
            type(intent) is not bytes or len(intent) > 8192 or
            type(proof_ref) is not str or not ID.fullmatch(proof_ref)
            or proof_ref in self.revoked):
            return False
        record = self.proofs.get(proof_ref)
        if type(record) is not dict or set(record) != {"payload", "signature"}:
            return False
        payload = record["payload"]
        signature = record["signature"]
        fields = {
            "schema", "role", "issuer", "key_id", "proof_ref", "audience",
            "intent_sha256", "issued_at", "expires_at", "decision",
            "subject", "external_effects", "site_id", "operation_id",
        }
        if type(payload) is not dict or set(payload) != fields:
            return False
        root = self.roots[role]
        if any((payload.get(k) != v) for k, v in {
            "schema": "imperial.gsc.signed-proof.v1",
            "role": role,
            "issuer": root.issuer,
            "key_id": root.key_id,
            "proof_ref": proof_ref,
            "audience": AUDIENCE,
            "decision": "APPROVE",
            "external_effects": "GOOGLE_SITEMAP_SUBMIT_ONLY",
        }.items()):
            return False
        try:
            intent_obj = json.loads(intent)
        except (ValueError, UnicodeError):
            return False
        if type(intent_obj) is not dict:
            return False
        if (payload["intent_sha256"] != hashlib.sha256(intent).hexdigest()
            or payload["site_id"] != intent_obj.get("site_id")
            or payload["operation_id"] != intent_obj.get("operation_id")
            or type(payload["subject"]) is not str
            or not ID.fullmatch(payload["subject"])):
            return False
        issued, expires = payload["issued_at"], payload["expires_at"]
        if (type(issued) is not int or type(expires) is not int
            or not issued <= self.now < expires
            or expires - issued > MAX_AGE
            or expires - issued < 1
            or type(signature) is not str or not SIG.fullmatch(signature)):
            return False
        try:
            sig_bytes = base64.b64decode(signature + "==",
                                         altchars=b"-_", validate=True)
            if len(sig_bytes) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(root.public_key_raw).verify(
                sig_bytes, DOMAIN + canonical(payload))
        except (InvalidSignature, ValueError, TypeError, OverflowError):
            return False
        return True

    def owner(self, intent: bytes, proof_ref: str) -> bool:
        return self._check("owner", intent, proof_ref)

    def qa(self, intent: bytes, proof_ref: str) -> bool:
        return self._check("qa", intent, proof_ref)

    def independent(self, owner_ref: str, qa_ref: str) -> bool:
        """Identity separation checks are in addition to distinct keys."""
        if (owner_ref == qa_ref or owner_ref not in self.proofs
            or qa_ref not in self.proofs):
            return False
        a = self.proofs[owner_ref].get("payload", {})
        b = self.proofs[qa_ref].get("payload", {})
        return (type(a) is dict and type(b) is dict
                and a.get("subject") != b.get("subject")
                and a.get("issuer") != b.get("issuer"))
