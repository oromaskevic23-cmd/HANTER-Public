# HANTER → Federated Orchestrator → NCA: Offline Execution Pilot

**Implementation maturity: E2 functional reference, with E3 unit checks subject to actual CI results. Not E5/E6 deployment.**

A standard-library Python reference demonstrates **one actual, local, read-only file-hashing task** through a policy-bound HANTER demo permit, federated route, NCA worker, separately authored QA checker and a durable local audit record. It does not invoke a model or execute arbitrary code.

## Reproduce (Python 3.11+)

From repository root:

    python3 -m unittest discover -s tests -p 'test_hanter_pilot.py' -v
    python3 -m hanter_pilot.pilot

The command uses a disposable temporary workspace with a randomly generated test key, synthetic source text and an SQLite database that is removed after the demo. No network or recurring background execution is used.

## Execution sequence

1. **HANTER demo intake:** signs a short-lived task using an HMAC-SHA256 test secret. This is **NOT a real AI Passport, Owner signature, or authorization to access production**.
2. **Federated route gate:** checks the permit, expiry, and exact tenant / orchestrator / NCA assignment.
3. **Guardian-style local rules:** allow only SHA256_FILE, zero expense, no external effects. This is a simulated policy gate, **not a deployed Guardian Core or Approval Gateway**.
4. **Replay hold:** SQLite BEGIN IMMEDIATE plus a unique key for tenant and job ID refuses duplicate tasks across connections. A failed job remains held for manual recovery design.
5. **NCA local worker:** reads at most 1 MiB from its tenant workspace and computes a true SHA-256 digest. Path traversal and symlinks are rejected.
6. **QA:** a separately authored in-process function reopens the file and checks both digest and byte count. This is a functional cross-check, **not independent human or organizational QA**.
7. **Audit:** records RESERVED followed by QA_PASSED or FAILED in a hash-chained SQLite journal. Alteration detection depends on a trusted separately retained chain anchor; this **is not a signed or tamper-proof production Audit Ledger**.

## Negative tests

Permit tampering and bad MAC; expired, future, and excessive TTL; incorrect tenant, orchestrator, or NCA; attempted spending or external side effects; arbitrary command action; directory traversal, absolute paths, backslashes and symlinks; missing and oversized files; replay after failure; QA rejection; and audit event editing.

## Ed25519 passport and separate signed decisions (sandbox-only)

The [Ed25519 AI Passport demonstration](ED25519_PASSPORT.md) adds a three-role, real-cryptographic-signature reference using **ephemeral test keys** for AI Passport, Guardian Core decision and Approval Gateway decision, all bound to a specific read-only NCA mission. It includes revocation snapshots, disabled-issuer rejection, stale-revocation failure and Owner Kill Switch tests. No actual external authority, runtime service, HSM, private server, owner signature or production permission exists.

    python3 -m pip install -r hanter_pilot/requirements-pilot.txt
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    python3 -m hanter_pilot.signed_demo

The older HMAC worker is still a local demonstration and is intentionally not described as a production AI Passport.

## Production blockers: mandatory before any real runtime

- Replace local HMAC demo permits with externally verifiable, signed and revocable AI Passport capabilities, trusted issuer and protected key custody.
- Implement authenticated real Guardian Core and Approval Gateway; Enterprise Skills restrict every action and resource.
- This Python worker is **not isolated from its host OS**. Path checks are NOT a security boundary against symlink race, mount attacks, hard links, or hostile tenants. Do not use for untrusted customer inputs or run untrusted code.
- SQLite is only a single-host replay demonstration: no distributed consensus, lease handoff, secure network transport or exactly-once delivery guarantees.
- Audit records need external anchoring, independently trusted signatures, access separation, retention and independent reviewer evidence.
- Add isolated browser/container workers, authorized local LLM inference, independent QA and recoverable distributed queues in a separately approved sandbox.
- No payments, custody, financial trades, customer publication, cloud costs, always-on monitoring, live deployments or billion-agent throughput are demonstrated or authorized.

**Authority boundary:** Architect / Alexander Nikolaevich Romaskevich (RomaskevicH) → HANTER → Federated Domain Orchestrators → NCA Teams → Bounded Execution. ORION synthesizes intelligence without execution authority. Preserve ProofGraph, IntentLock, Owner Kill Switch, Zero Trust, Public/Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary.

Long-term registration-scale design: [Nano Core Agents billion-plus architecture PR #12](https://github.com/oromaskevic23-cmd/Nano-Core-Agents-Public/pull/12), which is not evidence of a deployed fleet.

This file does not amend the repository LICENSE, existing author provenance, third-party rights or Owner approvals.

**Build software. Verify everything.**
