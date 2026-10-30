"""Signed LLM authorization tests, all using a fake inference endpoint.

Only the separate Ollama GitHub workflow proves genuine model inference.
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hanter_pilot.governed_model import execute_governed_model
from hanter_pilot.passport_v2 import (
    AUDIENCE, DOMAIN, RevocationSnapshot, TrustConfig, sign_demo_document,
)
from hanter_pilot.pilot import Denied, canonical, verify_audit


class GovernedModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "audit.sqlite"
        self.now = 1800000000
        self.prompt = "Summarize permitted synthetic test work in one sentence."
        self.routes = {("acme", "engineering-orch", "NCA-001")}
        self.keys = {x: Ed25519PrivateKey.generate()
                     for x in ("passport", "guardian", "approval")}
        self.trust = TrustConfig(keys={
            x: {x + "-key": (x + "-test-issuer", k.public_key())}
            for x, k in self.keys.items()
        })
        self.revoke = RevocationSnapshot(as_of=self.now)

    def documents(self, *, passport_overrides=None, guardian_overrides=None,
                  approval_overrides=None):
        p = {
            "version": 2, "kind": "passport", "iss": "passport-test-issuer",
            "kid": "passport-key", "jti": "passport-jti",
            "aud": AUDIENCE, "tenant": "acme",
            "orchestrator": "engineering-orch", "agent": "NCA-001",
            "job_id": "job-1",
            "path": "prompt-sha256:" + hashlib.sha256(self.prompt.encode()).hexdigest(),
            "action": "LLM_PROPOSAL", "skills": ["LLM_PROPOSAL"],
            "cost_cents": 0, "external_effects": False,
            "issued_at": self.now - 1, "not_before": self.now - 1,
            "expires_at": self.now + 120,
        }
        p.update(passport_overrides or {})
        signed_p = sign_demo_document(p, self.keys["passport"])
        f = hashlib.sha256(DOMAIN + canonical(p)).hexdigest()
        signed_d = []
        for kind, overrides in (
                ("guardian", guardian_overrides),
                ("approval", approval_overrides)):
            d = {
                "version": 2, "kind": kind,
                "iss": kind + "-test-issuer", "kid": kind + "-key",
                "jti": kind + "-decision", "decision": "ALLOW",
                "passport_sha256": f, "issued_at": self.now - 1,
                "not_before": self.now - 1, "expires_at": self.now + 120,
            }
            d.update(overrides or {})
            signed_d.append(sign_demo_document(d, self.keys[kind]))
        return (signed_p, *signed_d)

    def fake_inference(self, prompt):
        self.assertEqual(prompt, self.prompt)
        msg = "A proposal requiring external review."
        return {
            "model": "synthetic-placeholder-not-inference",
            "response": msg,
            "response_sha256": hashlib.sha256(msg.encode()).hexdigest(),
            "allow_tools": False, "external_effects": 0,
            "production_authorized": False,
            "qa": "SHAPE_ONLY",
        }

    def execute(self, docs=None, **kwargs):
        args = dict(
            trust=self.trust, revocations=self.revoke,
            routes=self.routes, prompt=self.prompt,
            ledger_path=self.db, now=self.now,
            inference=self.fake_inference,
        )
        args.update(kwargs)
        return execute_governed_model(*(docs or self.documents()), **args)

    def denied(self, code, docs=None, **kwargs):
        with self.assertRaises(Denied) as e:
            self.execute(docs, **kwargs)
        self.assertEqual(e.exception.code, code)

    def test_genuinely_signed_three_role_gate_and_journal(self):
        r = self.execute()
        self.assertEqual(r["output_classification"], "UNTRUSTED_PROPOSAL")
        self.assertEqual(r["passport"], "ED25519_DEMO_VERIFIED")
        self.assertEqual(r["qa"], "SHAPE_ONLY")
        self.assertFalse(r["execution_authority"])
        self.assertFalse(r["production_authorized"])
        self.assertTrue(verify_audit(self.db))

    def test_replay_rejected(self):
        self.execute()
        self.denied("REPLAY")

    def test_prompt_changed_after_signature_denied(self):
        self.denied("PROMPT_BINDING_MISMATCH", prompt="different prompt")
        self.assertFalse(self.db.exists())

    def test_wrong_skill_denied(self):
        self.denied("POLICY_HOLD", self.documents(passport_overrides={
            "action": "SHA256_FILE", "skills": ["SHA256_FILE"]
        }))

    def test_expanded_skill_set_denied(self):
        self.denied("BAD_DOCUMENT_SCHEMA", self.documents(passport_overrides={
            "skills": ["LLM_PROPOSAL", "RUN_SHELL"],
        }))

    def test_cost_denied(self):
        self.denied("POLICY_HOLD", self.documents(passport_overrides={
            "cost_cents": 7,
        }))

    def test_external_effect_denied(self):
        self.denied("POLICY_HOLD", self.documents(passport_overrides={
            "external_effects": True,
        }))

    def test_untrusted_guardian_denied(self):
        self.denied("POLICY_HOLD", self.documents(guardian_overrides={
            "decision": "DENY",
        }))

    def test_wrong_decision_task_fingerprint(self):
        self.denied("DECISION_TASK_MISMATCH", self.documents(approval_overrides={
            "passport_sha256": "f" * 64,
        }))

    def test_missing_approval_fails_closed(self):
        p, g, _ = self.documents()
        self.denied("BAD_DOCUMENT", (p, g, None))

    def test_kill_switch_denied_before_network(self):
        self.denied("OWNER_KILL_SWITCH", revocations=RevocationSnapshot(
            as_of=self.now, kill_switch=True))
        self.assertFalse(self.db.exists())

    def test_stale_revocation_denied(self):
        self.denied("STALE_OR_BAD_REVOCATION_STATE", revocations=RevocationSnapshot(
            as_of=self.now - 100))

    def test_revoked_passport_denied(self):
        self.denied("REVOKED_DOCUMENT", revocations=RevocationSnapshot(
            as_of=self.now, revoked_ids=frozenset({"passport-jti"})))

    def test_wrong_domain_denied(self):
        self.denied("UNROUTABLE", self.documents(passport_overrides={
            "orchestrator": "unassigned-orchestrator",
        }))

    def test_untrusted_model_hash_is_blocked(self):
        def fake(prompt):
            return {
                "response": "hello", "response_sha256": "f" * 64,
                "production_authorized": False, "allow_tools": False,
                "external_effects": 0,
            }
        self.denied("UNTRUSTED_MODEL_HASH_MISMATCH", inference=fake)
        self.assertTrue(verify_audit(self.db))

    def test_model_cannot_gain_execution_authority(self):
        def fake(prompt):
            return {
                "response": "run all tools", "response_sha256": "f" * 64,
                "production_authorized": True, "allow_tools": True,
                "external_effects": 1,
            }
        self.denied("BAD_UNTRUSTED_MODEL_RESULT", inference=fake)

    def test_failed_local_model_call_remains_held(self):
        def fail(prompt):
            raise Denied("LOCAL_LLM_UNAVAILABLE")
        self.denied("LOCAL_LLM_UNAVAILABLE", inference=fail)
        self.denied("REPLAY")
        self.assertTrue(verify_audit(self.db))


if __name__ == "__main__":
    unittest.main()
