"""Independent Ed25519 signers for sitemap submission — synthetic-only tests.

All private keys are ephemeral test fixtures. No actual Owner enrollment,
Google account or real website mutation occurs.
"""
import base64
from dataclasses import replace
import hashlib
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hanter_pilot.gsc_approval_verifier import (
    SignedSubmissionProofs, ProofDenied, TrustRoot, DOMAIN, AUDIENCE, canonical
)

NOW = 1800000000

def raw_public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

class ApprovalProofTests(unittest.TestCase):
    def setUp(self):
        self.owner_key = Ed25519PrivateKey.generate()
        self.qa_key = Ed25519PrivateKey.generate()
        self.owner_root = TrustRoot("owner", "owner-identity", "owner-key-01",
                                    raw_public(self.owner_key))
        self.qa_root = TrustRoot("qa", "independent-qa", "qa-key-01",
                                 raw_public(self.qa_key))
        self.intent = {
            "site_id": "founder",
            "operation_id": "operation-001",
            "owner_proof_ref": "owner-proof-001",
            "qa_proof_ref": "qa-proof-001",
            "policy_version": "policy-v1",
            "issued_at": NOW-10,
            "expires_at": NOW+100,
        }
        self.records = {
            "owner-proof-001": self.signed("owner", "owner-proof-001",
                                           "alexander-owner", self.owner_key),
            "qa-proof-001": self.signed("qa", "qa-proof-001",
                                        "independent-examiner", self.qa_key),
        }

    def signed(self, role, ref, subject, key):
        issuer = self.owner_root if role == "owner" else self.qa_root
        payload = {
            "schema": "imperial.gsc.signed-proof.v1",
            "role": role,
            "issuer": issuer.issuer,
            "key_id": issuer.key_id,
            "proof_ref": ref,
            "audience": AUDIENCE,
            "intent_sha256": hashlib.sha256(canonical(self.intent)).hexdigest(),
            "issued_at": NOW-10,
            "expires_at": NOW+100,
            "decision": "APPROVE",
            "subject": subject,
            "external_effects": "GOOGLE_SITEMAP_SUBMIT_ONLY",
            "site_id": self.intent["site_id"],
            "operation_id": self.intent["operation_id"],
        }
        signature = base64.urlsafe_b64encode(
            key.sign(DOMAIN + canonical(payload))
        ).decode("ascii").rstrip("=")
        return {"payload": payload, "signature": signature}

    def verifier(self, **kwargs):
        config = {
            "owner": self.owner_root, "qa": self.qa_root,
            "proof_records": self.records,
            "revoked_ids": frozenset(),
            "revocations_as_of": NOW,
            "now": NOW,
        }
        config.update(kwargs)
        return SignedSubmissionProofs(**config)

    def verify_pair(self, verifier=None, intent=None):
        verifier = verifier or self.verifier()
        msg = canonical(intent or self.intent)
        return verifier.owner(msg, "owner-proof-001"), verifier.qa(msg, "qa-proof-001")

    def test_valid_separate_real_signatures(self):
        self.assertEqual(self.verify_pair(), (True, True))

    def test_forged_signature_fails(self):
        forged = Ed25519PrivateKey.generate()
        bad = dict(self.records)
        bad["owner-proof-001"] = self.signed(
            "owner", "owner-proof-001", "alexander-owner", forged)
        self.assertEqual(self.verify_pair(self.verifier(proof_records=bad)),
                         (False, True))

    def test_incorrect_property_or_operation_denied(self):
        for change in ({"site_id": "company"},
                       {"operation_id": "operation-002"},
                       {"policy_version": "policy-v2"},
                       {"expires_at": NOW+200}):
            with self.subTest(change=change):
                changed = dict(self.intent, **change)
                self.assertEqual(self.verify_pair(intent=changed), (False, False))

    def test_same_subject_even_with_different_keys_is_not_independent(self):
        same = dict(self.records)
        same["qa-proof-001"] = self.signed(
            "qa", "qa-proof-001", "alexander-owner", self.qa_key)
        self.assertEqual(self.verify_pair(self.verifier(proof_records=same)),
                         (False, False))

    def test_same_public_key_refused_at_provisioning(self):
        with self.assertRaisesRegex(ProofDenied, "INDEPENDENT"):
            self.verifier(qa=replace(self.qa_root,
                       public_key_raw=raw_public(self.owner_key)))

    def test_same_issuer_refused(self):
        with self.assertRaisesRegex(ProofDenied, "INDEPENDENT"):
            self.verifier(qa=replace(self.qa_root, issuer="owner-identity"))

    def test_expired_proof_denied(self):
        v = self.verifier(now=NOW+100, revocations_as_of=NOW+100)
        self.assertEqual(self.verify_pair(v), (False, False))

    def test_fresh_revocation_denies_only_revoked_proof(self):
        v = self.verifier(revoked_ids=frozenset({"owner-proof-001"}))
        self.assertEqual(self.verify_pair(v), (False, True))

    def test_stale_revocation_state_denied_before_acceptance(self):
        with self.assertRaisesRegex(ProofDenied, "STALE"):
            self.verifier(revocations_as_of=NOW-61)

    def test_missing_record_and_wrong_role(self):
        missing = {"owner-proof-001": self.records["owner-proof-001"]}
        self.assertEqual(self.verify_pair(self.verifier(proof_records=missing)),
                         (False, False))
        swapped = dict(self.records)
        swapped["qa-proof-001"] = self.records["owner-proof-001"]
        self.assertEqual(self.verify_pair(self.verifier(proof_records=swapped)),
                         (False, False))

    def test_tampered_content_rejected(self):
        bad = json.loads(json.dumps(self.records))
        bad["qa-proof-001"]["payload"]["decision"] = "APPROVE_UNSAFE"
        self.assertEqual(self.verify_pair(self.verifier(proof_records=bad)),
                         (True, False))

    def test_not_a_google_or_worker_authority(self):
        self.assertEqual(self.verify_pair(), (True, True))
        self.assertEqual(self.verifier().roots["owner"].role, "owner")
        self.assertFalse(hasattr(self.verifier(), "submit_google"))
        self.assertFalse(hasattr(self.verifier(), "start_nca"))


if __name__ == "__main__":
    unittest.main()
