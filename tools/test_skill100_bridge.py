"""Adversarial tests for first signed, one-worker HANTER↔Skill100 lab."""
import copy
import unittest
from pathlib import Path

from hanter_pilot.pilot import Denied
from hanter_pilot.skill100_bridge import (
    AGENT_ID, bind_skill, fixed_synthetic_mission, run_one_ephemeral_lab,
    synthetic_source,
)

SKILL_ROOT=Path("pinned-skill")


class HANTERSkill100IntegrationTests(unittest.TestCase):
    def test_pinned_manifest_exam_federation_bind(self):
        bound=bind_skill(skill_root=SKILL_ROOT,mission=fixed_synthetic_mission())
        self.assertEqual(bound["agent_id"],AGENT_ID)
        self.assertEqual(bound["planned_subagents"],100)
        self.assertEqual(bound["planned_squads"],10)
        self.assertEqual(bound["planned_batches"],10)
        self.assertEqual(bound["jobs_dispatched_by_skill"],0)
        self.assertFalse(bound["execution_authorized"])
        self.assertGreater(len(synthetic_source(bound)),100)

    def test_real_local_hash_with_ephemeral_role_separated_signatures(self):
        report=run_one_ephemeral_lab(
            skill_root=SKILL_ROOT,mission=fixed_synthetic_mission(),
            allow_test_fixture=True,
        )
        self.assertEqual(report["agent_id"],AGENT_ID)
        self.assertEqual(report["actual_local_readonly_jobs"],1)
        self.assertTrue(report["test_passport_signature_verified"])
        self.assertTrue(report["test_guardian_signature_verified"])
        self.assertTrue(report["test_approval_signature_verified"])
        self.assertTrue(report["local_qa_double_hash_pass"])
        self.assertTrue(report["local_audit_chain_verified"])
        self.assertEqual(report["production_workers_online"],0)
        self.assertFalse(report["real_ai_passport_issued"])
        self.assertFalse(report["production_authorized"])
        self.assertFalse(report["external_independent_qa_verified"])

    def test_synthetic_gate_requires_explicit_opt_in(self):
        with self.assertRaises(Denied):
            run_one_ephemeral_lab(skill_root=SKILL_ROOT,mission=fixed_synthetic_mission())

    def test_owner_kill_switch_prevents_worker_execution(self):
        with self.assertRaisesRegex(Denied,"OWNER_KILL_SWITCH"):
            run_one_ephemeral_lab(
                skill_root=SKILL_ROOT,mission=fixed_synthetic_mission(),
                allow_test_fixture=True,owner_kill_switch=True)

    def test_revoked_passport_prevents_execution(self):
        with self.assertRaisesRegex(Denied,"REVOKED_DOCUMENT"):
            run_one_ephemeral_lab(
                skill_root=SKILL_ROOT,mission=fixed_synthetic_mission(),
                allow_test_fixture=True,revoke_passport=True)

    def test_tampered_approval_prevents_execution(self):
        with self.assertRaises(Denied):
            run_one_ephemeral_lab(
                skill_root=SKILL_ROOT,mission=fixed_synthetic_mission(),
                allow_test_fixture=True,mutate_approval=True)

    def test_cross_tenant_and_scope_tampering_rejected(self):
        for change in (
            {"tenant_id":"other-tenant"},
            {"orchestrator_id":"security-orch"},
            {"runtime_domain":"SECURITY_DEFENSIVE"},
            {"agent_count":99},
            {"max_parallel":11},
            {"external_effects":True},
            {"spending_usd":1},
            {"owner_kill_switch_engaged":False},
            {"source_sha256":"a"},
        ):
            with self.subTest(change=change),self.assertRaises(Denied):
                bind_skill(skill_root=SKILL_ROOT,mission={
                    **fixed_synthetic_mission(),**change})

    def test_extra_fields_and_noncanonical_input_denied(self):
        m=fixed_synthetic_mission()
        m["production_authorized"]=True
        with self.assertRaises(Denied):
            bind_skill(skill_root=SKILL_ROOT,mission=m)

    def test_missing_manifest_denied(self):
        with self.assertRaises(Denied):
            bind_skill(skill_root=Path("nonexistent-skill-root"),mission=fixed_synthetic_mission())


if __name__=="__main__":
    unittest.main()
