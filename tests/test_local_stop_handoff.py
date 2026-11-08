"""Synthetic HANTER/Owner stop handoff; keys never represent real authorities."""
import base64
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hanter_pilot.local_stop_handoff import (
    HANTER_DOMAIN, OWNER_DOMAIN, cosign_owner_local_stop,
)
from hanter_pilot.pilot import Denied, canonical


class LocalStopHandoffTests(unittest.TestCase):
    def setUp(self):
        self.owner = Ed25519PrivateKey.generate()
        self.hanter = Ed25519PrivateKey.generate()
        self.now = 1800000000
        self.payload = {
            "schema": "imperial.nca.local-stop.v1", "action": "STOP",
            "scope": "LOCAL_NODE", "node_id": "LAB-NODE-001",
            "tenant_id": "LAB-TENANT", "orchestrator_id": "ORCH-SOFTWARE",
            "worker_id": "NCA-WORKER-001", "reason": "Synthetic test stop",
            "nonce": "a" * 32, "issued_at": self.now - 1,
            "expires_at": self.now + 30,
        }
        self.routes = {("LAB-NODE-001", "LAB-TENANT", "ORCH-SOFTWARE", "NCA-WORKER-001")}

    def owner_sign(self, payload=None, signer=None):
        raw = canonical(self.payload if payload is None else payload)
        sig = (signer or self.owner).sign(OWNER_DOMAIN + raw)
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")

    def cosign(self, payload=None, signature=None, **overrides):
        body = self.payload if payload is None else payload
        args = dict(owner_public_key=self.owner.public_key(),
                    hanter_private_key=self.hanter, routes=self.routes,
                    revoked=lambda: False, clock=lambda: self.now)
        args.update(overrides)
        return cosign_owner_local_stop(body, self.owner_sign(body) if signature is None else signature,
                                       **args)

    def denied(self, expected, payload=None, signature=None, **kwargs):
        with self.assertRaises(Denied) as exc:
            self.cosign(payload, signature, **kwargs)
        self.assertEqual(exc.exception.code, expected)

    def test_valid_owner_command_is_detached_and_signed_by_hanter(self):
        result = self.cosign()
        raw = canonical(result["payload"])
        self.owner.public_key().verify(base64.urlsafe_b64decode(result["owner_signature"] + "=="),
                                       OWNER_DOMAIN + raw)
        self.hanter.public_key().verify(base64.urlsafe_b64decode(result["hanter_signature"] + "=="),
                                        HANTER_DOMAIN + raw)
        self.payload["reason"] = "Changed after co-signing"
        self.assertNotEqual(self.payload["reason"], result["payload"]["reason"])

    def test_wrong_owner_and_tampering_denied(self):
        self.denied("STOP_OWNER_SIGNATURE_INVALID", signature=self.owner_sign(
            signer=Ed25519PrivateKey.generate()))
        old = self.owner_sign()
        p = {**self.payload, "reason": "Changed after signing"}
        self.denied("STOP_OWNER_SIGNATURE_INVALID", p, old)
        self.denied("STOP_OWNER_SIGNATURE_INVALID", signature="bad")

    def test_same_owner_and_hanter_key_denied(self):
        self.denied("SEPARATE_TRUST_ROOTS_REQUIRED", hanter_private_key=self.owner)

    def test_unknown_route_scope_and_action_denied(self):
        for change, code in (({"tenant_id": "OTHER-TENANT"}, "STOP_ROUTE_DENIED"),
                             ({"orchestrator_id": "OTHER-ORCH"}, "STOP_ROUTE_DENIED"),
                             ({"worker_id": "OTHER-WORKER"}, "STOP_ROUTE_DENIED"),
                             ({"scope": "ALL_ORGANIZATIONS"}, "STOP_SCOPE_DENIED"),
                             ({"action": "RESTART"}, "STOP_SCOPE_DENIED")):
            with self.subTest(change=change):
                self.denied(code, {**self.payload, **change})

    def test_expired_future_nonce_and_unknown_fields_denied(self):
        for change, code in (({"expires_at": self.now}, "STOP_EXPIRED"),
                             ({"issued_at": self.now + 1}, "STOP_EXPIRED"),
                             ({"expires_at": self.now + 120}, "STOP_EXPIRED"),
                             ({"nonce": "bad"}, "STOP_SCHEMA_DENIED"),
                             ({"extra": True}, "STOP_SCHEMA_DENIED")):
            with self.subTest(change=change):
                self.denied(code, {**self.payload, **change})

    def test_revoked_or_unknown_revocation_denied(self):
        self.denied("STOP_ISSUER_REVOKED", revoked=lambda: True)
        self.denied("STOP_REVOCATION_UNAVAILABLE", revoked=lambda: None)
        states = iter((False, True))
        self.denied("STOP_ISSUER_REVOKED", revoked=lambda: next(states))

    def test_clock_rollback_and_expiry_during_check_denied(self):
        clock = iter((self.now, self.now - 1))
        self.denied("STOP_CLOCK_MOVED_BACKWARDS", clock=lambda: next(clock))
        clock = iter((self.now, self.now + 30))
        self.denied("STOP_EXPIRED", clock=lambda: next(clock))
        self.denied("STOP_CLOCK_INVALID", clock=lambda: None)


if __name__ == "__main__":
    unittest.main()
