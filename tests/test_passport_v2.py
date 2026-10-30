"""Adversarial unit checks for the offline Ed25519 reference trust chain."""

import hashlib
import secrets
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hanter_pilot.passport_v2 import (
    AUDIENCE, DOMAIN, RevocationSnapshot, TrustConfig,
    execute_signed_demo, sign_demo_document,
)
from hanter_pilot.pilot import Denied, canonical, verify_audit


class SignedPassportGatesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "workspace"
        self.file = self.workspace / "acme" / "evidence.txt"
        self.file.parent.mkdir(parents=True)
        self.file.write_bytes(b"HANTER verified test-only engineering data\n")
        self.ledger = self.root / "events.sqlite"
        self.now = 1800000000
        self.secret = secrets.token_bytes(32)
        self.routes = {("acme", "engineering-orch", "NCA-001")}
        self.private = {k: Ed25519PrivateKey.generate() for k in
                        ("passport", "guardian", "approval")}
        self.issuer = {
            "passport": "hanter-test-issuer",
            "guardian": "guardian-test-issuer",
            "approval": "gateway-test-issuer",
        }
        self.kid = {"passport": "passport-key-v1",
                    "guardian": "guardian-key-v1",
                    "approval": "approval-key-v1"}
        self.trust = TrustConfig(keys={
            k: {self.kid[k]: (self.issuer[k], self.private[k].public_key())}
            for k in self.private
        })
        self.revocations = RevocationSnapshot(as_of=self.now)
        self.passport_data = {
            "version": 2, "kind": "passport", "iss": self.issuer["passport"],
            "kid": self.kid["passport"], "jti": "passport-1",
            "aud": AUDIENCE, "tenant": "acme",
            "orchestrator": "engineering-orch", "agent": "NCA-001",
            "job_id": "job-1", "path": "evidence.txt",
            "action": "SHA256_FILE", "skills": ["SHA256_FILE"],
            "cost_cents": 0, "external_effects": False,
            "issued_at": self.now - 1, "not_before": self.now - 1,
            "expires_at": self.now + 120,
        }
        self.documents = self.docs()

    def signed(self, kind, payload):
        return sign_demo_document(payload, self.private[kind])

    def docs(self, passport_overrides=None, guardian_overrides=None,
             approval_overrides=None):
        payload = dict(self.passport_data)
        payload.update(passport_overrides or {})
        passport = self.signed("passport", payload)
        fingerprint = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
        decisions = []
        for kind, overrides in (
                ("guardian", guardian_overrides), ("approval", approval_overrides)):
            decision = {
                "version": 2, "kind": kind, "iss": self.issuer[kind],
                "kid": self.kid[kind], "jti": f"{kind}-1",
                "decision": "ALLOW", "passport_sha256": fingerprint,
                "issued_at": self.now - 1, "not_before": self.now - 1,
                "expires_at": self.now + 100,
            }
            decision.update(overrides or {})
            decisions.append(self.signed(kind, decision))
        return passport, *decisions

    def run_signed(self, documents=None, **kwargs):
        passport, guardian, approval = (documents if documents is not None
                                        else self.documents)
        args = dict(trust=self.trust, revocations=self.revocations,
                    secret=self.secret, routes=self.routes,
                    workspace=self.workspace, ledger_path=self.ledger,
                    now=self.now)
        args.update(kwargs)
        return execute_signed_demo(passport, guardian, approval, **args)

    def deny(self, code, documents=None, **kwargs):
        with self.assertRaises(Denied) as ctx:
            self.run_signed(documents, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        self.assertFalse(self.ledger.exists(),
                         "Access rejection must occur before any work or audit write")

    def test_triple_verified_signatures_perform_genuine_read_only_job(self):
        output = self.run_signed()
        self.assertEqual(output["sha256"],
                         hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertEqual(output["qa"], "PASS_LOCAL_DOUBLE_HASH")
        self.assertEqual(output["passport"], "ED25519_DEMO_VERIFIED")
        self.assertEqual(output["approval_gateway"], "SIGNED_DEMO_ALLOW")
        self.assertEqual(output["guardian"], "SIGNED_DEMO_ALLOW")
        self.assertEqual(output["external_effects"], 0)
        self.assertFalse(output["production_authorized"])
        self.assertTrue(verify_audit(self.ledger))

    def test_execution_replay_denied(self):
        self.run_signed()
        with self.assertRaises(Denied) as ctx:
            self.run_signed()
        self.assertEqual(ctx.exception.code, "REPLAY")

    def test_unsigned_passport_denied(self):
        p, g, a = self.documents
        self.deny("BAD_DOCUMENT", ({"payload": p["payload"]}, g, a))

    def test_tampered_passport_signature_denied(self):
        p, g, a = self.documents
        p = {**p, "payload": {**p["payload"], "tenant": "other"}}
        self.deny("INVALID_SIGNATURE", (p, g, a))

    def test_forged_approval_denied(self):
        p, g, a = self.documents
        changed = {**a, "payload": {**a["payload"], "decision": "DENY"}}
        self.deny("POLICY_HOLD", (p, g, changed))

    def test_untrusted_issuer_denied(self):
        self.deny("UNTRUSTED_ISSUER", self.docs(
            passport_overrides={"iss": "impostor"}))

    def test_wrong_issuer_key_signature_denied(self):
        p, g, a = self.documents
        forged_p = sign_demo_document(p["payload"], Ed25519PrivateKey.generate())
        self.deny("INVALID_SIGNATURE", (forged_p, g, a))

    def test_bad_signature_encoding_denied(self):
        p, g, a = self.documents
        self.deny("INVALID_SIGNATURE",
                  ({**p, "signature": "not-base64@"}, g, a))

    def test_wrong_audience_denied(self):
        self.deny("WRONG_AUDIENCE", self.docs(
            passport_overrides={"aud": "another-service"}))

    def test_wrong_agent_denied(self):
        self.deny("UNROUTABLE", self.docs(
            passport_overrides={"agent": "NCA-999"}))

    def test_wrong_orchestrator_denied(self):
        self.deny("UNROUTABLE", self.docs(
            passport_overrides={"orchestrator": "global-superuser"}))

    def test_wrong_tenant_denied(self):
        self.deny("UNROUTABLE", self.docs(
            passport_overrides={"tenant": "another-tenant"}))

    def test_extra_capability_denied(self):
        self.deny("BAD_DOCUMENT_SCHEMA", self.docs(
            passport_overrides={"skills": ["SHA256_FILE", "RUN_SHELL"]}))

    def test_nonzero_spend_denied(self):
        self.deny("POLICY_HOLD", self.docs(
            passport_overrides={"cost_cents": 1}))

    def test_side_effect_permission_denied(self):
        self.deny("POLICY_HOLD", self.docs(
            passport_overrides={"external_effects": True}))

    def test_arbitrary_command_denied(self):
        self.deny("POLICY_HOLD", self.docs(
            passport_overrides={"action": "RUN_SHELL"}))

    def test_passport_revoked_denied(self):
        self.deny("REVOKED_DOCUMENT", revocations=RevocationSnapshot(
            as_of=self.now, revoked_ids=frozenset({"passport-1"})))

    def test_guardian_revoked_denied(self):
        self.deny("REVOKED_DOCUMENT", revocations=RevocationSnapshot(
            as_of=self.now, revoked_ids=frozenset({"guardian-1"})))

    def test_approval_revoked_denied(self):
        self.deny("REVOKED_DOCUMENT", revocations=RevocationSnapshot(
            as_of=self.now, revoked_ids=frozenset({"approval-1"})))

    def test_issuer_disabled_denied(self):
        self.deny("DISABLED_ISSUER", revocations=RevocationSnapshot(
            as_of=self.now,
            disabled_issuers=frozenset({self.issuer["passport"]})))

    def test_owner_kill_switch_denied(self):
        self.deny("OWNER_KILL_SWITCH", revocations=RevocationSnapshot(
            as_of=self.now, kill_switch=True))

    def test_stale_revocations_denied(self):
        self.deny("STALE_OR_BAD_REVOCATION_STATE",
                  revocations=RevocationSnapshot(as_of=self.now - 61))

    def test_future_revocation_snapshot_denied(self):
        self.deny("STALE_OR_BAD_REVOCATION_STATE",
                  revocations=RevocationSnapshot(as_of=self.now + 1))

    def test_passport_expired_denied(self):
        self.deny("INVALID_DOCUMENT_TIME", self.docs(passport_overrides={
            "issued_at": self.now - 180, "not_before": self.now - 180,
            "expires_at": self.now - 1,
        }))

    def test_guardian_expired_denied(self):
        self.deny("INVALID_DOCUMENT_TIME", self.docs(guardian_overrides={
            "issued_at": self.now - 180, "not_before": self.now - 180,
            "expires_at": self.now - 1,
        }))

    def test_approval_not_yet_valid_denied(self):
        self.deny("INVALID_DOCUMENT_TIME", self.docs(approval_overrides={
            "not_before": self.now + 5,
        }))

    def test_overlong_passport_denied(self):
        self.deny("INVALID_DOCUMENT_TIME", self.docs(passport_overrides={
            "expires_at": self.now + 601,
        }))

    def test_denied_guardian_decision(self):
        self.deny("POLICY_HOLD", self.docs(guardian_overrides={
            "decision": "DENY",
        }))

    def test_denied_approval_decision(self):
        self.deny("POLICY_HOLD", self.docs(approval_overrides={
            "decision": "DENY",
        }))

    def test_guardian_bound_to_different_task_denied(self):
        self.deny("DECISION_TASK_MISMATCH", self.docs(guardian_overrides={
            "passport_sha256": "0" * 64,
        }))

    def test_approval_bound_to_different_task_denied(self):
        self.deny("DECISION_TASK_MISMATCH", self.docs(approval_overrides={
            "passport_sha256": "f" * 64,
        }))

    def test_guardian_cannot_impersonate_approval(self):
        p, g, a = self.documents
        self.deny("BAD_DOCUMENT_SCHEMA", (p, g, g))

    def test_missing_approval_denied(self):
        p, g, a = self.documents
        self.deny("BAD_DOCUMENT", (p, g, None))

    def test_unknown_passport_claim_denied(self):
        self.deny("BAD_DOCUMENT_SCHEMA", self.docs(passport_overrides={
            "role": "admin",
        }))

    def test_boolean_cost_denied(self):
        self.deny("BAD_DOCUMENT_SCHEMA", self.docs(passport_overrides={
            "cost_cents": False,
        }))


if __name__ == "__main__":
    unittest.main()
