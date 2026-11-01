"""Short-lived Ed25519 sandbox authorities, NOT real Owner-issued AI Passports."""
from __future__ import annotations
import hashlib
import os
import secrets
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hanter_pilot.passport_v2 import (
    AUDIENCE, DOMAIN, RevocationSnapshot, TrustConfig, _verify, sign_demo_document,
)
from hanter_pilot.pilot import Denied, canonical

AGENT = "IMPERIAL-JOHNNY-WALKER-001"  # Wave 1, slot 36, CODE_ENGINEERING
ORCHESTRATOR = "engineering-orch"
TENANT = "imperial-ci"

def issue_test_only(prompt_sha256: str, *, now: int | None = None):
    """Create three fresh ephemeral issuers for a narrowly scoped no-effect exam."""
    if type(prompt_sha256) is not str or len(prompt_sha256)!=64 or any(c not in "0123456789abcdef" for c in prompt_sha256):
        raise Denied("INVALID_PROMPT_FINGERPRINT")
    now = int(time.time()) if now is None else now
    private = {role: Ed25519PrivateKey.generate() for role in ("passport","guardian","approval")}
    issuers = {r: r+"-ephemeral-ci" for r in private}
    trust = TrustConfig(keys={r: {r+"-ci": (issuers[r],private[r].public_key())} for r in private})
    passport_payload = {
        "version":2, "kind":"passport", "iss":issuers["passport"], "kid":"passport-ci",
        "jti":"ci-passport-"+secrets.token_hex(12), "aud":AUDIENCE,
        "tenant":TENANT, "orchestrator":ORCHESTRATOR, "agent":AGENT,
        "job_id":"exam-"+secrets.token_hex(9),
        "path":"prompt-sha256:"+prompt_sha256,
        "action":"LLM_PROPOSAL","skills":["LLM_PROPOSAL"],
        "cost_cents":0,"external_effects":False,
        "issued_at":now,"not_before":now,"expires_at":now+180,
    }
    passport=sign_demo_document(passport_payload,private["passport"])
    bound=hashlib.sha256(DOMAIN+canonical(passport_payload)).hexdigest()
    decisions=[]
    for role in ("guardian","approval"):
        payload={"version":2,"kind":role,"iss":issuers[role],"kid":role+"-ci",
                 "jti":role+"-ci-"+secrets.token_hex(10),
                 "decision":"ALLOW","passport_sha256":bound,
                 "issued_at":now,"not_before":now,"expires_at":now+180}
        decisions.append(sign_demo_document(payload,private[role]))
    return passport,decisions[0],decisions[1],trust

def verify_test_only(passport,guardian,approval,trust,*,prompt_sha256,now:int,revoked=frozenset()):
    """No model invocation may precede this fail-closed check."""
    if os.environ.get("IMPERIAL_OWNER_KILL_SWITCH","1")!="0":
        raise Denied("OWNER_KILL_SWITCH")
    if os.environ.get("HANTER_CI_EXAM_OPT_IN")!="CI_SANDBOX_ONLY":
        raise Denied("EXPLICIT_TEST_OPT_IN_REQUIRED")
    snapshot=RevocationSnapshot(as_of=now,revoked_ids=revoked,kill_switch=False)
    p=_verify(passport,kind="passport",trust=trust,revocations=snapshot,now=now)
    if (p["aud"]!=AUDIENCE or
        (p["tenant"],p["orchestrator"],p["agent"])!=(TENANT,ORCHESTRATOR,AGENT) or
        p["path"]!="prompt-sha256:"+prompt_sha256 or
        p["action"]!="LLM_PROPOSAL" or p["skills"]!=["LLM_PROPOSAL"] or
        p["cost_cents"]!=0 or p["external_effects"] is not False):
        raise Denied("PASSPORT_SCOPE_DENIED")
    fingerprint=hashlib.sha256(DOMAIN+canonical(p)).hexdigest()
    for role,doc in (("guardian",guardian),("approval",approval)):
        decision=_verify(doc,kind=role,trust=trust,revocations=snapshot,now=now)
        if decision["passport_sha256"]!=fingerprint:
            raise Denied("DECISION_PASSPORT_MISMATCH")
    return {"agent_id":AGENT,"tenant":TENANT,"orchestrator":ORCHESTRATOR,
            "skill":"LLM_PROPOSAL","cryptography":"ED25519_EPHEMERAL_TEST",
            "signed_role_count":3,"real_owner_authorized":False,
            "production_authorized":False,"external_effects_allowed":False}
