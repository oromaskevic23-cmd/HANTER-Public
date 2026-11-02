"""Separate read-only acceptance of HANTER's ephemeral synthetic receipt.

This verifier neither trusts a claimed PASS nor signs/executes a worker.
It independently re-derives the exact synthetic input bytes from pinned
IMPERIAL Skill, checks route/evidence and rejects all production claims.
This is process-separated functional QA, NOT external independent certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from hanter_pilot.skill100_bridge import (
    AGENT_ID, PINNED_SKILL_COMMIT, bind_skill, fixed_synthetic_mission,
    synthetic_source,
)

FIELDS=frozenset({
    "schema", "skill_source_commit", "skill_id", "skill_manifest_sha256",
    "skill_exam_sha256", "fleet_plan_sha256", "task_sha256", "agent_id",
    "tenant_id", "orchestrator_id", "artifact_sha256", "artifact_bytes",
    "test_passport_signature_verified", "test_guardian_signature_verified",
    "test_approval_signature_verified", "local_qa_double_hash_pass",
    "local_audit_chain_verified", "actual_local_readonly_jobs",
    "production_workers_online", "owner_approval_production_verified",
    "real_ai_passport_issued", "external_independent_qa_verified",
    "production_authorized", "spending_usd",
})


def verify_receipt(*, skill_root: Path, receipt: object) -> bool:
    if type(receipt) is not dict or set(receipt) != FIELDS:
        return False
    bound=bind_skill(skill_root=skill_root,mission=fixed_synthetic_mission())
    source=synthetic_source(bound)
    expected={
        "schema":"imperial.hanter.skill100.lab-receipt.v1",
        "skill_source_commit":PINNED_SKILL_COMMIT,
        "skill_id":bound["skill_id"],
        "skill_manifest_sha256":bound["skill_manifest_sha256"],
        "skill_exam_sha256":bound["skill_exam_sha256"],
        "fleet_plan_sha256":bound["fleet_plan_sha256"],
        "task_sha256":bound["task_sha256"],
        "agent_id":AGENT_ID,
        "tenant_id":bound["tenant_id"],
        "orchestrator_id":bound["orchestrator_id"],
        "artifact_sha256":hashlib.sha256(source).hexdigest(),
        "artifact_bytes":len(source),
        "test_passport_signature_verified":True,
        "test_guardian_signature_verified":True,
        "test_approval_signature_verified":True,
        "local_qa_double_hash_pass":True,
        "local_audit_chain_verified":True,
        "actual_local_readonly_jobs":1,
        "production_workers_online":0,
        "owner_approval_production_verified":False,
        "real_ai_passport_issued":False,
        "external_independent_qa_verified":False,
        "production_authorized":False,
        "spending_usd":0,
    }
    return all(type(receipt[k]) is type(v) and receipt[k]==v
               for k,v in expected.items())


def main():
    parser=argparse.ArgumentParser(description="Independent read-only synthetic receipt inspector")
    parser.add_argument("--skill-root",type=Path,default=Path("pinned-skill"))
    parser.add_argument("--receipt",type=Path,required=True)
    args=parser.parse_args()
    if args.receipt.is_symlink() or args.receipt.stat().st_size > 16384:
        raise SystemExit("QA_RECEIPT_NOT_TRUSTED")
    try:
        receipt=json.loads(args.receipt.read_text(encoding="utf-8"))
    except (ValueError,UnicodeError,OSError):
        raise SystemExit("QA_RECEIPT_INVALID")
    if not verify_receipt(skill_root=args.skill_root,receipt=receipt):
        raise SystemExit("QA_RECEIPT_REJECTED")
    print("SKILL100_SYNTHETIC_RECEIPT_INDEPENDENT_RECHECK_PASS",
          "PRODUCTION_AUTHORIZED_FALSE", "EXTERNAL_INDEPENDENT_QA_FALSE")


if __name__=="__main__":
    main()
