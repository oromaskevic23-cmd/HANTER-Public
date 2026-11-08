"""Adversarial tests for offline Owner-root proof; ephemeral keys only."""
import base64
import copy
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hanter_pilot.owner_root_proof import (
    DOMAIN, OwnerRootProofGate, production_preflight,
)
from hanter_pilot.pilot import Denied, canonical


NOW=1800000000


def signature(key, claim):
    return base64.urlsafe_b64encode(
        key.sign(DOMAIN+canonical(claim))
    ).decode("ascii").rstrip("=")


def public_key(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class OwnerRootProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="owner-root-proof-test-")
        self.addCleanup(self.tmp.cleanup)
        self.key=Ed25519PrivateKey.generate()
        self.db=Path(self.tmp.name)/"trusted.sqlite"
        self.gate=OwnerRootProofGate(
            self.db,pinned_public_key=public_key(self.key),
            tenant_id="imperial-internal",key_id="owner-local-test",
        )

    def test_real_ed25519_proof_only_not_owner_deployment(self):
        claim=self.gate.issue_challenge(now=NOW)
        receipt=self.gate.verify(claim,signature(self.key,claim),now=NOW+1)
        self.assertTrue(receipt["signature_verified"])
        self.assertEqual(receipt["stage"],"OFFLINE_PINNED_KEY_POSSESSION_VERIFIED")
        for k in ("externally_attested_owner_identity",
                  "revocation_service_verified","real_ai_passport_issued",
                  "independent_qa_verified","worker_execution_authorized",
                  "production_authorized"):
            self.assertIs(receipt[k],False)

    def test_challenge_is_single_use_even_after_gate_restarts(self):
        claim=self.gate.issue_challenge(now=NOW)
        proof=signature(self.key,claim)
        self.gate.verify(claim,proof,now=NOW+1)
        again=OwnerRootProofGate(self.db,pinned_public_key=public_key(self.key),
                                tenant_id="imperial-internal",key_id="owner-local-test")
        with self.assertRaises(Denied):
            again.verify(claim,proof,now=NOW+2)

    def test_forged_key_denied_without_consuming_challenge(self):
        claim=self.gate.issue_challenge(now=NOW)
        forged=Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(Denied,"SIGNATURE"):
            self.gate.verify(claim,signature(forged,claim),now=NOW+1)
        receipt=self.gate.verify(claim,signature(self.key,claim),now=NOW+1)
        self.assertTrue(receipt["signature_verified"])

    def test_expired_and_future_challenges_denied(self):
        claim=self.gate.issue_challenge(now=NOW)
        with self.assertRaises(Denied):
            self.gate.verify(claim,signature(self.key,claim),now=NOW+300)
        with self.assertRaises(Denied):
            self.gate.verify(claim,signature(self.key,claim),now=NOW-1)

    def test_tampered_scope_signature_or_ttl_denied(self):
        claim=self.gate.issue_challenge(now=NOW)
        valid_sig=signature(self.key,claim)
        for extra in (
            {"production_authorized":True},
            {"external_effects":True},
            {"spending_usd":1},
            {"spending_usd":False},
            {"key_id":"other-key"},
            {"tenant_id":"other-tenant"},
            {"purpose":"AUTHORIZE_PRODUCTION"},
            {"expires_at":NOW+999},
            {"issued_at":True},
            {"nonce_hex":secrets.token_hex(32)},
            {"new_field":1},
        ):
            with self.subTest(extra=extra),self.assertRaises(Denied):
                self.gate.verify({**claim,**extra},valid_sig,now=NOW+1)

    def test_unknown_signed_nonce_denied(self):
        clone=OwnerRootProofGate(
            Path(self.tmp.name)/"other.sqlite",
            pinned_public_key=public_key(self.key),
            tenant_id="imperial-internal",key_id="owner-local-test",
        )
        claim=self.gate.issue_challenge(now=NOW)
        with self.assertRaisesRegex(Denied,"UNKNOWN_OR_CONSUMED"):
            clone.verify(claim,signature(self.key,claim),now=NOW+1)

    def test_invalid_signature_format_denied(self):
        claim=self.gate.issue_challenge(now=NOW)
        for value in ("", None,"a"*64,[],"!"*86):
            with self.subTest(value=value),self.assertRaises(Denied):
                self.gate.verify(claim,value,now=NOW+1)

    def test_challenge_expiring_during_database_wait_is_not_consumed(self):
        claim = self.gate.issue_challenge(now=NOW)
        proof = signature(self.key, claim)
        with patch("hanter_pilot.owner_root_proof.time.time", side_effect=(NOW+299, NOW+300)):
            with self.assertRaisesRegex(Denied, "OWNER_PROOF_EXPIRED"):
                self.gate.verify(claim, proof)
        self.assertTrue(self.gate.verify(claim, proof, now=NOW+1)["signature_verified"])

    def test_clock_rollback_during_database_wait_is_denied(self):
        claim = self.gate.issue_challenge(now=NOW)
        proof = signature(self.key, claim)
        with patch("hanter_pilot.owner_root_proof.time.time", side_effect=(NOW+2, NOW+1)):
            with self.assertRaisesRegex(Denied, "OWNER_PROOF_CLOCK_ROLLBACK"):
                self.gate.verify(claim, proof)
        self.assertTrue(self.gate.verify(claim, proof, now=NOW+1)["signature_verified"])

    def test_noncanonical_signature_encoding_is_rejected_without_consuming(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        claim = self.gate.issue_challenge(now=NOW)
        proof = signature(self.key, claim)
        index = alphabet.index(proof[-1])
        self.assertEqual(index % 16, 0)
        alternate = proof[:-1] + alphabet[index + 1]
        self.assertEqual(base64.urlsafe_b64decode(proof + "=="),
                         base64.urlsafe_b64decode(alternate + "=="))
        with self.assertRaisesRegex(Denied, "OWNER_PROOF_SIGNATURE_INVALID"):
            self.gate.verify(claim, alternate, now=NOW+1)
        self.assertTrue(self.gate.verify(claim, proof, now=NOW+1)["signature_verified"])

    def test_root_pin_is_mandatory(self):
        with self.assertRaises(Denied):
            OwnerRootProofGate(self.db,pinned_public_key=b"",
                               key_id="owner-local-test",tenant_id="imperial-internal")
        with self.assertRaises(Denied):
            OwnerRootProofGate(self.db,pinned_public_key=public_key(self.key),
                               key_id="x",tenant_id="imperial-internal")

    def test_symlink_database_denied(self):
        alias=Path(self.tmp.name)/"alias.sqlite"
        alias.symlink_to(self.db)
        with self.assertRaises(Denied):
            OwnerRootProofGate(alias,pinned_public_key=public_key(self.key),
                               key_id="owner-local-test",tenant_id="imperial-internal")

    def test_manual_ready_claims_never_start_workers(self):
        p=production_preflight(**{
            name:True for name in (
                "owner_identity_attested","passport_issuer_trusted",
                "guardian_service_trusted","approval_service_trusted",
                "independent_qa_trusted","sandbox_attested")
        })
        self.assertTrue(all(p["requirements_claimed"].values()))
        self.assertIs(p["production_authorized"],False)
        self.assertIs(p["worker_start_allowed"],False)
        self.assertIs(p["actual_signature_envelopes_checked"],False)


if __name__=="__main__":
    unittest.main()
