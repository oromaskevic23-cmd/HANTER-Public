"""Offline, reversible pilot tests: all tasks are local read-only SHA-256 jobs."""

import hashlib
import hmac
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hanter_pilot.pilot import (
    Denied, canonical, execute_demo, issue_demo_permit, local_demo, verify_audit,
)


class HANTERFederatedPilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.tenant = "tenant-A"
        self.file = self.workspace / self.tenant / "source.txt"
        self.file.parent.mkdir(parents=True)
        self.file.write_bytes(b"verified engineering output\n")
        self.db = self.root / "evidence.sqlite"
        self.secret = b"test-only-symmetric-permit-key-32-bytes-please"
        self.now = 1800000000
        self.routes = {("tenant-A", "orch-engineering", "NCA-001")}

    def request(self, **kwargs):
        args = dict(tenant=self.tenant, orchestrator="orch-engineering",
                    agent="NCA-001", job_id="mission-1",
                    path="source.txt", now=self.now)
        args.update(kwargs)
        return issue_demo_permit(self.secret, **args)

    def execute(self, request=None, **kwargs):
        args = dict(secret=self.secret, routes=self.routes,
                    workspace=self.workspace, ledger_path=self.db, now=self.now)
        args.update(kwargs)
        return execute_demo(request if request is not None else self.request(), **args)

    def denied(self, expected_code, request=None, **kwargs):
        with self.assertRaises(Denied) as err:
            self.execute(request, **kwargs)
        self.assertEqual(err.exception.code, expected_code)

    def test_worker_performs_real_read_and_local_qa(self):
        result = self.execute()
        self.assertEqual(result["sha256"], hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertEqual(result["bytes"], len(self.file.read_bytes()))
        self.assertEqual(result["qa"], "PASS_LOCAL_DOUBLE_HASH")
        self.assertEqual(result["external_effects"], 0)
        self.assertIs(result["production_authorized"], False)
        self.assertTrue(verify_audit(self.db))

    def test_persistent_replay_rejected(self):
        self.execute()
        self.denied("REPLAY")
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM claims").fetchone()[0], 1)

    def test_forged_payload_is_denied(self):
        p = self.request()
        p["payload"]["tenant"] = "tenant-B"
        self.denied("BAD_SIGNATURE", p)

    def test_invalid_mac(self):
        p = self.request()
        p["mac"] = "0" * 64
        self.denied("BAD_SIGNATURE", p)

    def test_wrong_key_is_denied(self):
        self.denied("BAD_SIGNATURE", secret=b"x" * 32)

    def test_expired(self):
        self.denied("EXPIRED_OR_INVALID_TTL", self.request(ttl=1),
                    now=self.now + 2)

    def test_excessive_lease_ttl(self):
        self.denied("EXPIRED_OR_INVALID_TTL", self.request(ttl=301))

    def test_future_dated(self):
        self.denied("EXPIRED_OR_INVALID_TTL",
                    self.request(now=self.now + 45))

    def test_cross_orchestrator_is_denied(self):
        self.denied("UNROUTABLE", self.request(orchestrator="other"))

    def test_cross_agent_is_denied(self):
        self.denied("UNROUTABLE", self.request(agent="NCA-002"))

    def test_cross_tenant_is_denied(self):
        self.denied("UNROUTABLE", self.request(tenant="tenant-B"))

    def test_nonzero_spend_is_denied(self):
        self.denied("POLICY_HOLD", self.request(cost_cents=1))

    def test_side_effect_flag_is_denied(self):
        self.denied("POLICY_HOLD", self.request(external_effects=True))

    def test_arbitrary_execution_is_denied(self):
        self.denied("POLICY_HOLD", self.request(action="RUN_SHELL"))

    def test_parent_traversal_is_denied(self):
        self.denied("INVALID_PATH", self.request(path="../outside"))

    def test_absolute_path_is_denied(self):
        self.denied("INVALID_PATH", self.request(path="/etc/passwd"))

    def test_backslash_path_is_denied(self):
        self.denied("INVALID_PATH", self.request(path=r"..\outside"))

    def test_symbolic_link_is_denied(self):
        outside = self.root / "secret.txt"
        outside.write_text("not for the NCA")
        (self.file.parent / "link.txt").symlink_to(outside)
        self.denied("INVALID_PATH", self.request(path="link.txt"))

    def test_missing_file_is_denied(self):
        self.denied("FILE_MISSING", self.request(path="missing.txt"))

    def test_oversized_file_stays_failed_and_replay_blocked(self):
        self.file.write_bytes(b"x" * 1_048_577)
        self.denied("FILE_TOO_LARGE")
        self.assertTrue(verify_audit(self.db))
        self.file.write_bytes(b"short")
        self.denied("REPLAY")

    def test_independent_qa_failure_stays_failed(self):
        with patch("hanter_pilot.pilot.verify_file_independently", return_value=False):
            self.denied("QA_FAILED")
        self.assertTrue(verify_audit(self.db))
        with sqlite3.connect(self.db) as con:
            row = con.execute("SELECT state FROM claims").fetchone()
            self.assertEqual(row[0], "FAILED")

    def test_hash_chain_detects_modified_event(self):
        self.execute()
        self.assertTrue(verify_audit(self.db))
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE audit SET artifact='tampered' WHERE state='QA_PASSED'")
        self.assertFalse(verify_audit(self.db))

    def test_nonserializable_permit_body_fails_closed(self):
        p = self.request()
        p["payload"]["path"] = b"not valid JSON"
        self.denied("BAD_SCHEMA", p)
        self.assertFalse(self.db.exists())

    def test_bad_schema_rejected_before_replay_claim(self):
        p = self.request()
        p["payload"]["extra"] = "unapproved"
        self.denied("BAD_SCHEMA", p)
        self.assertFalse(self.db.exists())

    def test_demo_cli_api(self):
        result = local_demo()
        self.assertTrue(result["audit_chain_valid"])
        self.assertEqual(result["qa"], "PASS_LOCAL_DOUBLE_HASH")


if __name__ == "__main__":
    unittest.main()
