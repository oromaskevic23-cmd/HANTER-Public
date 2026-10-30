"""Run an ephemeral, signed, three-authority NCA demonstration.

No private key is written to disk. No network, customer inputs, account logins,
payments, LLM inference, server deployment or recurring background execution.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .passport_v2 import (
    AUDIENCE, DOMAIN, RevocationSnapshot, TrustConfig,
    execute_signed_demo, sign_demo_document,
)
from .pilot import canonical, verify_audit


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hanter-signed-offline-") as root:
        workspace = Path(root) / "workspace"
        target = workspace / "demo-tenant" / "source.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"IMPERIAL Core - signed HANTER / federated NCA demo\n")
        now = int(time.time())

        roles = ("passport", "guardian", "approval")
        private_keys = {role: Ed25519PrivateKey.generate() for role in roles}
        issuers = {role: f"{role}-ephemeral-issuer" for role in roles}
        key_ids = {role: f"{role}-ephemeral-key" for role in roles}
        trust = TrustConfig(keys={
            role: {key_ids[role]: (issuers[role], private_keys[role].public_key())}
            for role in roles
        })
        passport_payload = {
            "version": 2, "kind": "passport",
            "iss": issuers["passport"], "kid": key_ids["passport"],
            "jti": "ephemeral-passport-1", "aud": AUDIENCE,
            "tenant": "demo-tenant", "orchestrator": "engineering-orch",
            "agent": "NCA-LOCAL-001", "job_id": "synthetic-readonly-1",
            "path": "source.txt", "action": "SHA256_FILE",
            "skills": ["SHA256_FILE"], "cost_cents": 0,
            "external_effects": False, "issued_at": now,
            "not_before": now, "expires_at": now + 120,
        }
        passport = sign_demo_document(passport_payload, private_keys["passport"])
        fingerprint = hashlib.sha256(DOMAIN + canonical(passport_payload)).hexdigest()
        decisions = []
        for role in ("guardian", "approval"):
            claim = {
                "version": 2, "kind": role, "iss": issuers[role],
                "kid": key_ids[role], "jti": f"synthetic-{role}-1",
                "decision": "ALLOW", "passport_sha256": fingerprint,
                "issued_at": now, "not_before": now,
                "expires_at": now + 120,
            }
            decisions.append(sign_demo_document(claim, private_keys[role]))
        audit = Path(root) / "audit.sqlite"
        result = execute_signed_demo(
            passport, decisions[0], decisions[1],
            trust=trust, revocations=RevocationSnapshot(as_of=now),
            secret=secrets.token_bytes(32),
            routes={("demo-tenant", "engineering-orch", "NCA-LOCAL-001")},
            workspace=workspace, ledger_path=audit, now=now,
        )
        result["audit_chain_valid"] = verify_audit(audit)
        result["scope"] = "offline-synthetic-readonly-demo"
        result["security_assertion"] = "not-production-authorized"
        print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
