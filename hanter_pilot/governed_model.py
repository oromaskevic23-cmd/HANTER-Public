"""Guarded local LLM proposal path: Ed25519 -> Guardian -> Approval -> NCA.

This is an offline/loopback demo with ephemeral issuer trust, not a deployed
service or real owner authorization. The model output is permanently untrusted.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from .ollama_local import model_proposal
from .passport_v2 import (
    AUDIENCE, DOMAIN, MAX_REVOCATION_AGE,
    RevocationSnapshot, TrustConfig, _verify,
)
from .pilot import Denied, _append, _connect, canonical

SKILL = "LLM_PROPOSAL"


def execute_governed_model(
    passport: dict, guardian_decision: dict, approval_decision: dict,
    *, trust: TrustConfig, revocations: RevocationSnapshot,
    routes: set[tuple[str, str, str]], prompt: str,
    ledger_path: Path, now: int, inference=model_proposal,
) -> dict:
    """Require independently signed authorization before a local model request."""
    if (type(now) is not int or type(revocations.as_of) is not int
            or type(revocations.kill_switch) is not bool
            or not isinstance(revocations.revoked_ids, frozenset)
            or not isinstance(revocations.disabled_issuers, frozenset)
            or revocations.as_of > now
            or now - revocations.as_of > MAX_REVOCATION_AGE):
        raise Denied("STALE_OR_BAD_REVOCATION_STATE")
    if revocations.kill_switch:
        raise Denied("OWNER_KILL_SWITCH")
    if type(prompt) is not str or not 0 < len(prompt) <= 2000:
        raise Denied("BAD_PROMPT")
    p = _verify(passport, kind="passport", trust=trust,
                revocations=revocations, now=now)
    if p["aud"] != AUDIENCE:
        raise Denied("WRONG_AUDIENCE")
    if (p["tenant"], p["orchestrator"], p["agent"]) not in routes:
        raise Denied("UNROUTABLE")
    if (p["action"] != SKILL or p["skills"] != [SKILL]
            or p["cost_cents"] != 0 or p["external_effects"]):
        raise Denied("POLICY_HOLD")
    # Reuse the v2 'path' signed resource field strictly as a content hash for
    # this non-file action. It is never used as a filesystem path.
    expected_resource = "prompt-sha256:" + hashlib.sha256(prompt.encode()).hexdigest()
    if p["path"] != expected_resource:
        raise Denied("PROMPT_BINDING_MISMATCH")
    fingerprint = hashlib.sha256(DOMAIN + canonical(p)).hexdigest()
    g = _verify(guardian_decision, kind="guardian", trust=trust,
                revocations=revocations, now=now)
    a = _verify(approval_decision, kind="approval", trust=trust,
                revocations=revocations, now=now)
    if g["passport_sha256"] != fingerprint or a["passport_sha256"] != fingerprint:
        raise Denied("DECISION_TASK_MISMATCH")

    # Local demonstration only: SQLite is not a distributed durable queue.
    tenant, job = p["tenant"], p["job_id"]
    with _connect(ledger_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            con.execute(
                "INSERT INTO claims (tenant,job_id,state) VALUES (?,?,?)",
                (tenant, job, "RESERVED"),
            )
        except sqlite3.IntegrityError:
            raise Denied("REPLAY") from None
        _append(con, tenant, job, "RESERVED")

    try:
        result = inference(prompt)
        if (type(result) is not dict or result.get("production_authorized") is not False
                or result.get("allow_tools") is not False
                or result.get("external_effects") != 0
                or type(result.get("response_sha256")) is not str
                or len(result["response_sha256"]) != 64
                or type(result.get("response")) is not str):
            raise Denied("BAD_UNTRUSTED_MODEL_RESULT")
        digest = hashlib.sha256(result["response"].encode()).hexdigest()
        if digest != result["response_sha256"]:
            raise Denied("UNTRUSTED_MODEL_HASH_MISMATCH")
    except Exception:
        with _connect(ledger_path) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE claims SET state='FAILED' WHERE tenant=? AND job_id=?",
                (tenant, job),
            )
            _append(con, tenant, job, "FAILED")
        raise
    with _connect(ledger_path) as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute(
            "UPDATE claims SET state='PROPOSAL_RECEIVED' WHERE tenant=? AND job_id=?",
            (tenant, job),
        )
        _append(con, tenant, job, "PROPOSAL_RECEIVED", digest)

    return {
        **result,
        "job_id": job, "tenant": tenant,
        "agent": p["agent"], "orchestrator": p["orchestrator"],
        "passport": "ED25519_DEMO_VERIFIED",
        "guardian": "SIGNED_DEMO_ALLOW",
        "approval_gateway": "SIGNED_DEMO_ALLOW",
        "audit": "LOCAL_HASH_CHAIN_ONLY",
        "output_classification": "UNTRUSTED_PROPOSAL",
        "execution_authority": False,
        "production_authorized": False,
    }
