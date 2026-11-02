"""HANTER ↔ IMPERIAL Skill 100-subagent, one-job *ephemeral laboratory* bridge.

Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
Pins a source-only Skill and runs exactly one real SHA256_FILE task via HANTER's
existing test-Ed25519 gate. It neither enrolls the Owner nor deploys any agent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .pilot import ACTION, Denied, canonical, verify_audit
from .passport_v2 import (
    AUDIENCE, DOMAIN, RevocationSnapshot, TrustConfig, execute_signed_demo,
    sign_demo_document,
)

SKILL_ID = "imperial.skill.subagents-100"
AGENT_ID = "NCA-SUB-001"
LAB_INPUT_PREFIX = "IMPERIAL_CORE_SKILL100_LAB_V1\n"
PINNED_SKILL_COMMIT = "3ae7ccc86d5e0329723ae3beb5a79ea22cdc3861"


def fixed_synthetic_mission() -> dict:
    """Safe, data-only test input; never read private files or credentials."""
    return {
        "schema": "imperial.skill.subagents-100.mission.v1",
        "tenant_id": "imperial-internal",
        "orchestrator_id": "engineering-orch",
        "runtime_domain": "CODE_ENGINEERING",
        "mission_id": "HANTER-LAB-100",
        "source_sha256": hashlib.sha256(b"synthetic authorized input\n").hexdigest(),
        "agent_count": 100,
        "max_parallel": 10,
        "owner_kill_switch_engaged": True,
        "external_effects": False,
        "spending_usd": 0,
    }


def bind_skill(*, skill_root: Path, mission: dict) -> dict:
    """Verify the registered, pinned Skill and return ONE blocked route.

    Does not import from the internet, launch agents, or turn plan admission
    into permission to execute. The origin Git SHA is enforced by pinned CI checkout;
    this function separately verifies descriptor/exam content.
    """
    try:
        from imperial_skill.manifest import read_json_strict, manifest_digest
        from imperial_skill.exams import validate_exam
        from imperial_skill.registry import SkillRegistry
        from imperial_skill.subagents_100 import plan_subagents_100, plan_batches
        manifest_path = skill_root / "examples/skills/subagents-100.json"
        exam_path = skill_root / "examples/exams/subagents-100.json"
        if (skill_root.is_symlink() or manifest_path.is_symlink()
                or exam_path.is_symlink()
                or manifest_path.stat().st_size > 65536
                or exam_path.stat().st_size > 65536):
            raise Denied("SKILL_SOURCE_INVALID")
        manifest = read_json_strict(manifest_path.read_bytes())
        exam = read_json_strict(exam_path.read_bytes())
        exam_digest = validate_exam(exam)["exam_sha256"]
        if (manifest["skill_id"] != SKILL_ID
                or manifest["version"] != "0.1.0"
                or exam["skill_id"] != SKILL_ID
                or exam["version"] != manifest["version"]
                or exam_digest != manifest["exam_sha256"]
                or manifest["runtime_domain"] != "CODE_ENGINEERING"
                or manifest["tenant_id"] != mission["tenant_id"]
                or manifest["orchestrator_id"] != mission["orchestrator_id"]):
            raise Denied("SKILL_CONTRACT_MISMATCH")
        registry = SkillRegistry()
        registry.register(manifest)
        registry_plan = registry.resolve(
            tenant_id=mission["tenant_id"], orchestrator_id=mission["orchestrator_id"],
            runtime_domain=mission["runtime_domain"], skill_id=SKILL_ID, version="0.1.0")
        plan = plan_subagents_100(mission)
        batches = plan_batches(plan)
        if (registry_plan["execution_authorized"] is not False
                or plan["agent_count"] != 100
                or plan["owner_kill_switch_engaged"] is not True
                or plan["execution_authorized"] is not False
                or batches["jobs_dispatched"] != 0
                or plan["roster"][0]["agent_id"] != AGENT_ID):
            raise Denied("SKILL_NOT_READ_ONLY")
        return {
            "skill_id": SKILL_ID, "skill_version": "0.1.0",
            "skill_manifest_sha256": manifest_digest(manifest),
            "skill_exam_sha256": exam_digest,
            "skill_registry_plan_sha256": registry_plan["plan_sha256"],
            "fleet_plan_sha256": plan["plan_sha256"],
            "agent_id": plan["roster"][0]["agent_id"],
            "task_sha256": plan["roster"][0]["task_sha256"],
            "tenant_id": mission["tenant_id"],
            "orchestrator_id": mission["orchestrator_id"],
            "planned_subagents": 100, "planned_squads": 10,
            "planned_batches": batches["batch_count"],
            "jobs_dispatched_by_skill": 0,
            "execution_authorized": False, "production_authorized": False,
        }
    except Denied:
        raise
    except (OSError, KeyError, TypeError, ValueError, ImportError, AssertionError) as exc:
        raise Denied("SKILL_VALIDATION_FAILED") from exc


def synthetic_source(binding: dict) -> bytes:
    if binding.get("agent_id") != AGENT_ID:
        raise Denied("WRONG_FIRST_AGENT")
    return (
        LAB_INPUT_PREFIX + binding["fleet_plan_sha256"] + "\n"
        + binding["task_sha256"] + "\n"
    ).encode("ascii")


def run_one_ephemeral_lab(*, skill_root: Path, mission: dict,
                          allow_test_fixture: bool = False,
                          owner_kill_switch: bool = False,
                          revoke_passport: bool = False,
                          mutate_approval: bool = False) -> dict:
    """Actually read/hash one synthetic file using existing HANTER local worker.

    Ephemeral test signing keys are in-memory and NON-PRODUCTION. This is not
    actual Owner key enrollment, independent service QA, or a server deployment.
    """
    if allow_test_fixture is not True:
        raise Denied("EXPLICIT_SYNTHETIC_TEST_OPT_IN_REQUIRED")
    binding = bind_skill(skill_root=skill_root, mission=mission)
    source = synthetic_source(binding)
    now = int(time.time())
    with tempfile.TemporaryDirectory(prefix="hanter-skill100-test-") as tmp:
        workspace = Path(tmp) / "workspace"
        path = workspace / binding["tenant_id"] / "source.txt"
        path.parent.mkdir(parents=True)
        path.write_bytes(source)
        roles = ("passport", "guardian", "approval")
        keys = {r: Ed25519PrivateKey.generate() for r in roles}
        issuers = {r: f"{r}-skill100-test-issuer" for r in roles}
        key_ids = {r: f"{r}-skill100-test-key" for r in roles}
        trust = TrustConfig(keys={
            r: {key_ids[r]: (issuers[r], keys[r].public_key())} for r in roles
        })
        payload = {
            "version": 2, "kind": "passport",
            "iss": issuers["passport"], "kid": key_ids["passport"],
            "jti": secrets.token_hex(16), "aud": AUDIENCE,
            "tenant": binding["tenant_id"],
            "orchestrator": binding["orchestrator_id"], "agent": AGENT_ID,
            "job_id": "SKILL100-LAB-001", "path": "source.txt",
            "action": ACTION, "skills": [ACTION], "cost_cents": 0,
            "external_effects": False, "issued_at": now, "not_before": now,
            "expires_at": now + 120,
        }
        passport = sign_demo_document(payload, keys["passport"])
        fingerprint = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
        decisions = {}
        for role in ("guardian", "approval"):
            decision = {
                "version": 2, "kind": role,
                "iss": issuers[role], "kid": key_ids[role],
                "jti": secrets.token_hex(16), "decision": "ALLOW",
                "passport_sha256": fingerprint,
                "issued_at": now, "not_before": now, "expires_at": now + 120,
            }
            decisions[role] = sign_demo_document(decision, keys[role])
        if mutate_approval:
            decisions["approval"]["payload"]["passport_sha256"] = "0" * 64
        revocations = RevocationSnapshot(
            as_of=now, kill_switch=owner_kill_switch,
            revoked_ids=frozenset({payload["jti"]}) if revoke_passport else frozenset(),
        )
        ledger = Path(tmp) / "evidence.sqlite"
        worker_result = execute_signed_demo(
            passport, decisions["guardian"], decisions["approval"],
            trust=trust, revocations=revocations,
            secret=secrets.token_bytes(32),
            routes={(binding["tenant_id"], binding["orchestrator_id"], AGENT_ID)},
            workspace=workspace, ledger_path=ledger, now=now,
        )
        if (worker_result["sha256"] != hashlib.sha256(source).hexdigest()
                or worker_result["bytes"] != len(source)
                or worker_result["qa"] != "PASS_LOCAL_DOUBLE_HASH"
                or worker_result["agent"] != AGENT_ID
                or worker_result["production_authorized"] is not False
                or not verify_audit(ledger)):
            raise Denied("FIRST_WORKER_RESULT_OR_LOCAL_QA_FAILED")
        # Only non-secret evidence is returned. This is not an authorization receipt.
        return {
            "schema": "imperial.hanter.skill100.lab-receipt.v1",
            "skill_source_commit": PINNED_SKILL_COMMIT,
            "skill_id": binding["skill_id"],
            "skill_manifest_sha256": binding["skill_manifest_sha256"],
            "skill_exam_sha256": binding["skill_exam_sha256"],
            "fleet_plan_sha256": binding["fleet_plan_sha256"],
            "task_sha256": binding["task_sha256"],
            "agent_id": AGENT_ID,
            "tenant_id": binding["tenant_id"],
            "orchestrator_id": binding["orchestrator_id"],
            "artifact_sha256": worker_result["sha256"], "artifact_bytes": worker_result["bytes"],
            "test_passport_signature_verified": worker_result["passport"] == "ED25519_DEMO_VERIFIED",
            "test_guardian_signature_verified": worker_result["guardian"] == "SIGNED_DEMO_ALLOW",
            "test_approval_signature_verified": worker_result["approval_gateway"] == "SIGNED_DEMO_ALLOW",
            "local_qa_double_hash_pass": True,
            "local_audit_chain_verified": True,
            "actual_local_readonly_jobs": 1,
            "production_workers_online": 0,
            "owner_approval_production_verified": False,
            "real_ai_passport_issued": False,
            "external_independent_qa_verified": False,
            "production_authorized": False, "spending_usd": 0,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="One ephemeral HANTER + pinned Skill lab task")
    parser.add_argument("--skill-root", type=Path, default=Path("pinned-skill"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = run_one_ephemeral_lab(
        skill_root=args.skill_root, mission=fixed_synthetic_mission(),
        allow_test_fixture=True,
    )
    if args.output.is_symlink():
        raise Denied("OUTPUT_SYMLINK_DENIED")
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("HANTER_SKILL100_EPHEMERAL_LAB_PASS", receipt["agent_id"],
          "real_local_readonly_jobs", receipt["actual_local_readonly_jobs"],
          "production_authorized", receipt["production_authorized"])


if __name__ == "__main__":
    main()
