"""One genuine, locally governed LLM proposal using synthetic Ed25519 issuers.

This pilot does not confer production authority; no model output is executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .governed_model import execute_governed_model
from .passport_v2 import (
    AUDIENCE, DOMAIN, RevocationSnapshot, TrustConfig, sign_demo_document,
)
from .pilot import canonical, verify_audit


def main() -> None:
    if os.environ.get("HANTER_LOCAL_LLM_PROBE") != "I_ACCEPT_LOCAL_INFERENCE":
        raise SystemExit("Opt in with HANTER_LOCAL_LLM_PROBE=I_ACCEPT_LOCAL_INFERENCE")
    prompt = (
        "In one concise English sentence, explain why a software agent should "
        "obtain authorization before processing a synthetic file."
    )
    now = int(time.time())
    private = {role: Ed25519PrivateKey.generate()
               for role in ("passport", "guardian", "approval")}
    issuers = {role: role + "-ephemeral-issuer" for role in private}
    kids = {role: role + "-ephemeral-key" for role in private}
    trust = TrustConfig(keys={
        role: {kids[role]: (issuers[role], private[role].public_key())}
        for role in private
    })
    p = {
        "version": 2, "kind": "passport", "iss": issuers["passport"],
        "kid": kids["passport"], "jti": "model-demo-passport-1",
        "aud": AUDIENCE, "tenant": "demo-tenant",
        "orchestrator": "engineering-orch", "agent": "NCA-LOCAL-LLM-001",
        "job_id": "model-proposal-demo-1",
        "path": "prompt-sha256:" + hashlib.sha256(prompt.encode()).hexdigest(),
        "action": "LLM_PROPOSAL", "skills": ["LLM_PROPOSAL"],
        "cost_cents": 0, "external_effects": False,
        "issued_at": now, "not_before": now, "expires_at": now + 120,
    }
    passport = sign_demo_document(p, private["passport"])
    finger = hashlib.sha256(DOMAIN + canonical(p)).hexdigest()
    decisions = []
    for role in ("guardian", "approval"):
        d = {
            "version": 2, "kind": role, "iss": issuers[role],
            "kid": kids[role], "jti": role + "-decision-model-1",
            "decision": "ALLOW", "passport_sha256": finger,
            "issued_at": now, "not_before": now, "expires_at": now + 120,
        }
        decisions.append(sign_demo_document(d, private[role]))
    with tempfile.TemporaryDirectory(prefix="hanter-governed-llm-") as root:
        ledger = Path(root) / "audit.sqlite"
        result = execute_governed_model(
            passport, *decisions,
            trust=trust, revocations=RevocationSnapshot(as_of=now),
            routes={("demo-tenant", "engineering-orch", "NCA-LOCAL-LLM-001")},
            prompt=prompt, ledger_path=ledger, now=now,
        )
        evidence = {key: value for key, value in result.items() if key != "response"}
        evidence["response_characters"] = len(result["response"])
        evidence["audit_chain_valid"] = verify_audit(ledger)
        evidence["local_model_call_completed"] = True
        print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
