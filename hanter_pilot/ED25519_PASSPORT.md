# HANTER Ed25519 AI Passport — Three-Authority Offline Pilot

**Status: verified only when the linked GitHub Actions run succeeds; not production authorization.**

## Demonstrated contract

The experimental gateway validates three independently signed documents **before** invoking the existing bounded local NCA worker:

1. **AI Passport candidate** — an Ed25519 signature made by a locally trusted *ephemeral test issuer*, binding NCA identity, tenant, federated orchestrator, audience, job, skill, action, path, time window and FREE_ONLY/no-external-effects limitations.
2. **Guardian Core decision candidate** — separately signed, test-only allow decision, cryptographically bound to the exact Passport payload digest.
3. **Approval Gateway decision candidate** — another separately signed, test-only allow decision, also bound to the exact Passport payload digest.

The verifier does not trust claims from the task itself to select issuer keys. It selects independently supplied, role-separated public keys from a local trust fixture. The exact document schema, issue time, not-before, expiry (maximum five minutes), matching task digest, role identity, NCA routing, and resource scope are checked before the read-only worker is called.

## Revocation and emergency control

A **fresh local revocation snapshot** (maximum 60 seconds old) must be present. A revoked Passport, Guardian decision or Approval decision is denied, as is a disabled issuer. A set Owner Kill Switch blocks all operations before worker startup. Missing or stale snapshot is **fail closed**. The snapshot is supplied to the example by the local test harness; **there is no independent online revocation service, distributed state synchronization, key rotation infrastructure or tested kill-switch propagation time**.

## Execute one genuine read-only task

Python 3.11+:

    python3 -m pip install -r hanter_pilot/requirements-pilot.txt
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    python3 -m hanter_pilot.signed_demo

The demonstration creates three **temporary, independent Ed25519 private keys in process**, keeps all data under a temporary directory, signs a restricted local job and decisions, runs the existing NCA file-hash worker, checks QA and local hash-chain integrity and removes temporary data. It does not print or store the private keys. No accounts, customer information, LLMs, paid services or remote worker agents are accessed.

The direct-worker legacy reference is available separately:

    python3 -m hanter_pilot.pilot

## Acceptance and threat-boundary status

| Control | Evidence scope | Explicit limitation |
|---|---|---|
| Ed25519 signature verification | Real cryptographic primitive, role-separated ephemeral local keys | No installed Owner/trust authority, HSM or issuer infrastructure |
| Audience, mission and capabilities | Exact local schema, signed scope, zero-spend and no-effect checks | No remotely enforced Enterprise Skills service |
| Guardian and Approval | Two independently signed demo allow decisions bound to Passport hash | No real Guardian Core / Approval Gateway deployment or approval service |
| Revocation and Owner Kill Switch | Locally injected snapshot, stale-state denial and negative tests | Not a live signed, distributed, resilient revocation feed |
| At-most-once local claim | SQLite job reservation, reject replays | No distributed leases / consensus or exactly-once across external services |
| Execution | Real read-only SHA-256 of one synthetic file | No isolated sandbox, browser, arbitrary software engineering or LLM inference |
| Independent QA | Separate in-process re-hash implementation | Not an independent reviewer or independent process |
| Evidence integrity | Local hash chain detects modified entries | Not immutable/signed, not anchored to an external Audit Ledger |

## Non-negotiable deployment conditions

- Authoritative key issuance and custody, Ed25519 trust anchors, rotation, revocation persistence and rollback protection **outside** this repository.
- Protected policy source and independent authenticated services for real Guardian Core, Approval Gateway and AI Passport.
- Separate service and role boundaries for HANTER, federated orchestrators, NCA workers and ORION, preserving least privilege.
- Robust sandbox/container isolation, secure filesystem primitives, secret scoping, network deny rules, guaranteed cleanup and rate limits.
- Unambiguous signed Owner approval for high-risk operations; no Owner impersonation or conversion of an agent's suggestion into an approval.
- Durable, verifiable Audit Ledger with external anchoring; independent QA; runnable model integration when explicitly permitted; measurement of security, reliability and cost.
- No global unrestricted orchestrator, no CRYPTO IMPERIAL ecosystem cross-boundary actions, no unapproved spending, no automated publication, and no third-party-account access.

**Target architecture:** Architect → HANTER → Federated Domain Orchestrators → Professional Teams / NCA → Scoped Execution. ORION provides collective intelligence without independent execution authority. Keep ProofGraph, IntentLock, Enterprise Skills, Zero Trust, Public/Private Boundary, Owner Kill Switch and CRYPTO IMPERIAL Ecosystem Boundary.

**IP governance:** Original project rights and historical contributions remain governed by the repository root LICENSE and existing third-party notices. This prototype does not issue client licenses or invoke the founder's cryptographic brand seal.

**Founder and Final Architectural Decision Authority:** Alexander Nikolaevich Romaskevich — RomaskevicH.

**Build software. Verify everything.**
