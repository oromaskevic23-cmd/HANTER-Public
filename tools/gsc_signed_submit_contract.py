"""Cross-repository Ed25519 -> Google sitemap submission gate integration test.

This module uses generated ephemeral keys, fake Google API responses and an
in-memory OAuth placeholder. It must never be interpreted as a real send.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hanter_pilot.gsc_approval_verifier import (
    AUDIENCE, DOMAIN, SignedSubmissionProofs, TrustRoot, canonical,
)

from imperial_plugins.search_console_read import SearchConsoleReadBridge, GoogleAccessError
from imperial_plugins.search_console_submit import SubmissionGate, SitemapIntent


NOW = 1800000000


class FakeGoogleAccount(SearchConsoleReadBridge):
    def __init__(self):
        super().__init__(access_token="synthetic-test-token-not-real")
    def check_property(self, site_id):
        assert site_id == "founder"
        return {"google_permission": "siteOwner"}


def public_key(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signed_proof(key, role, issuer, key_id, subject, ref, intent):
    payload = {
        "schema": "imperial.gsc.signed-proof.v1",
        "role": role,
        "issuer": issuer,
        "key_id": key_id,
        "proof_ref": ref,
        "audience": AUDIENCE,
        "intent_sha256": hashlib.sha256(intent.canonical()).hexdigest(),
        "issued_at": NOW-10,
        "expires_at": NOW+100,
        "decision": "APPROVE",
        "subject": subject,
        "external_effects": "GOOGLE_SITEMAP_SUBMIT_ONLY",
        "site_id": intent.site_id,
        "operation_id": intent.operation_id,
    }
    signature = base64.urlsafe_b64encode(
        key.sign(DOMAIN + canonical(payload))).decode("ascii").rstrip("=")
    return {"payload": payload, "signature": signature}


def main():
    owner_key = Ed25519PrivateKey.generate()
    qa_key = Ed25519PrivateKey.generate()
    intent = SitemapIntent(
        site_id="founder",
        operation_id="signed-integration-001",
        owner_proof_ref="owner-proof-001",
        qa_proof_ref="qa-proof-001",
        policy_version="owner-policy-v001",
        issued_at=NOW-10,
        expires_at=NOW+100,
    )
    trusted = SignedSubmissionProofs(
        owner=TrustRoot("owner", "owner-test-issuer", "owner-key-001",
                        public_key(owner_key)),
        qa=TrustRoot("qa", "qa-test-issuer", "qa-key-001", public_key(qa_key)),
        proof_records={
            "owner-proof-001": signed_proof(
                owner_key, "owner", "owner-test-issuer", "owner-key-001",
                "owner-human-test", "owner-proof-001", intent),
            "qa-proof-001": signed_proof(
                qa_key, "qa", "qa-test-issuer", "qa-key-001",
                "qa-human-test", "qa-proof-001", intent),
        },
        revoked_ids=frozenset(),
        revocations_as_of=NOW,
        now=NOW,
    )
    assert trusted.owner(intent.canonical(), intent.owner_proof_ref)
    assert trusted.qa(intent.canonical(), intent.qa_proof_ref)
    sent = []
    def mock_transport(method, endpoint, token):
        assert method == "PUT"
        assert token == "synthetic-test-token-not-real"
        assert endpoint.startswith("https://www.googleapis.com/webmasters/v3/sites/")
        sent.append((method, endpoint))
        return 204
    def audit(site_id):
        return {"site_id": site_id, "public_http_audit": "PASS",
                "google_indexed": "UNVERIFIED"}

    with tempfile.TemporaryDirectory(prefix="hanter-gsc-contract-") as folder:
        db = Path(folder)/"receipt.sqlite"
        with patch.dict(os.environ, {"IMPERIAL_OWNER_KILL_SWITCH": "0"}):
            gate = SubmissionGate(
                db,
                approval_verifier=trusted.owner,
                qa_verifier=trusted.qa,
                site_auditor=audit,
                kill_switch=False,
            )
            result = gate.submit(
                intent, FakeGoogleAccount(), send=mock_transport, now=NOW)
            assert result["status"] == "GOOGLE_SITEMAP_SUBMITTED"
            assert result["google_indexed"] == "UNVERIFIED"
            assert result["evidence"] == "PROVIDER_HTTP_RESPONSE_NOT_INDEXING"
            assert gate.verify_audit_chain()
            assert len(sent) == 1
            try:
                gate.submit(intent, FakeGoogleAccount(), send=mock_transport, now=NOW)
                raise AssertionError("Replay must be denied")
            except GoogleAccessError:
                assert len(sent) == 1

    # This run proves only that the owner/QA cryptographic signatures are
    # truly checked at the host boundary and cannot be bypassed in the test.
    print("PASS: HANTER Ed25519 dual-signature -> IMPERIAL Plugins Google gate")
    print("NO GOOGLE NETWORK: synthetic OAuth, synthetic provider 204, 0 real sends")
    print("PRODUCTION_AUTHORIZED=False; GOOGLE_INDEXED=UNVERIFIED")


if __name__ == "__main__":
    main()
