# HANTER Signed NCA Pilot — Security Threat Model and Deployment Gates

**Status:** Security design and risk register for an **offline reference pilot**. No independent penetration test or production security assessment has been completed.

**Founder / Final Architectural Decision Authority:** Alexander Nikolaevich Romaskevich (RomaskevicH).  
**Date:** 2026-10-31. **Review before production:** mandatory.

## Trust assumptions

1. Local test-issuer key pairs are ephemeral, generated and used within the same GitHub Actions process; there is no verified external root of trust or signed Owner delegation.
2. The caller supplies the public-key trust fixture, revocation snapshot, route registry, workspace path and local HMAC worker secret. **These are privileged inputs, not authenticated services.** Any compromise at the caller can defeat the demonstration's gate.
3. No untrusted script/model output is executed, no network endpoint is contacted and no customer data is authorized.
4. All read-only work is a bounded file-hash task; the OS filesystem is trusted for this test, so path checks do not constitute a hardened worker boundary.
5. SQLite and its chain are mutable by the local account; no external checkpoint, signature or independent retention is present.
6. Success of the unit tests verifies individual synthetic scenarios only, not the absence of vulnerabilities, policy completeness or ability to scale.

## Risk register

| ID | Severity if production-exposed | Attack / failure | Existing offline control | Required before production |
| --- | --- | --- | --- | --- |
| TM-01 | Critical | Attacker replaces trusted issuer public keys | Role-key separation against an injected fixture | Protected, signed, independently maintained trust configuration with provenance, rotation and emergency suspension |
| TM-02 | Critical | Forged/stale revocation state permits a revoked agent | Locally provided snapshot freshness check | Strongly authenticated revocation feed, monotonic versions, durable rollback protection, rapid propagation and offline-deny posture |
| TM-03 | Critical | Runtime host compromised or malicious file races defeat path checks | Rejects common traversal and symlink cases | Containers/VMs, tenant-isolated UID/namespace, openat2/no-follow, secure mounts, network deny, cgroups and security review |
| TM-04 | High | Task replay after distributed failover | Local SQLite unique tenant/job reservation | Durable transactional inbox/outbox, authenticated leases, quorum/fencing as appropriate, regional fault injection |
| TM-05 | Critical | Guardian or Approval actor impersonation | Separate Ed25519 signatures on exact task hash | Real distinct trust domains, HSM-backed issuers, enforceable owner-approved policies, no auto-approving agents |
| TM-06 | High | Trust-key compromise / accidental secrets in logs | Temporary keys; CI shows no key material | Secret manager, access reviews, issuance audit, key lifecycle/rotation, signed key inventory, zero plaintext logs |
| TM-07 | High | Whole audit table rewritten, truncated, or reordered | Hash-chain checks local in-place modification | Independent append-only storage, anchored signatures, inclusion/consistency proofs, retention rules and external QA |
| TM-08 | High | File content altered between worker read and QA | Separate in-process rehash | Immutable content snapshots, fd-bound reads, artifact digest pinning, independently isolated QA and replay evidence |
| TM-09 | High | Unlimited task flood, resource exhaustion and cost leakage | Single-size-limit test file and FREE_ONLY predicate | Quotas, bounded queues, per-domain budgets, rate limits, metrics and account-level $0 spend guard |
| TM-10 | Critical | Cross-tenant data or unauthorized browser session | Exact tenant/agent/orchestrator claims in permit | Cryptographic tenant scoping, process and browser profile isolation, cleanup attestation, leakage regression |
| TM-11 | Critical | Prompt injection / model-generated authority escalation | No model is connected yet | Untrusted-output quarantine, tool allowlists, independent policy enforcement, scenario-based adversarial model tests |
| TM-12 | High | Unsafe automation of financial, public publishing or cryptographic assets | No external side effects or spending allowed | Explicit human-signed high-risk approval, independent receipt checks and CRYPTO IMPERIAL Ecosystem Boundary |
| TM-13 | High | Third-party or transitive package compromise | Direct cryptography library version pinned in pilot | SBOM, lock with transitive versions and approved hashes, signed provenance and dependency vulnerability scan |
| TM-14 | High | Revocation or Owner Kill Switch fails during network partition | Local snapshot is required; kill flag checked before execution | Signed kill-switch state, measurable propagation SLO, worker cancellation, reconciliation and recovery drills |
| TM-15 | Medium | Tests pass but model or real-world QA quality is poor | Functional double-hash verification only | Frozen independent evaluation set, human reviewer, model/provider version, reproducible quality metrics |

## Protected architecture

Architect / Owner → HANTER Command Center → independently authorized **Federated Domain Orchestrators** → professional NCA teams → isolated, leased workers.

ORION's collective intelligence does **not** create execution authority. Guardian Core, Enterprise Skills, AI Passport and Approval Gateway require independent trust and fail-closed checks. Audit Ledger and ProofGraph record evidence; IntentLock binds actual authorized outcomes. Zero Trust, Public/Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary always apply.

The one-billion-plus NCA figure is a future **registry scalability target**; no concurrently executing billion-agent claim is made.

## Release blockade checklist

No release can be called production-ready until all mandatory conditions have **external, inspectable evidence**:

- [ ] Architect-approved signed trust-anchor ownership and key lifecycle; issuer and approval separation.
- [ ] Authenticated and replay-resistant cross-process AI Passport issuance, expiry, revocation and state propagation, with documented failure handling.
- [ ] Deployed Guardian Core, Enterprise Skills and Approval Gateway with independent approval policy and protected public/private and crypto boundaries.
- [ ] Independent adversarial security QA for tenant escape, signature substitution, stale state, path races, tool injection and kill switch.
- [ ] Isolated worker execution with resource caps, per-agent browser isolation where used, no default network egress, safe cleanup and recovery.
- [ ] Distributed task claims, idempotency, durable audit, revocation and zero-dollar billing hard stops under real failure injection.
- [ ] External Audit Ledger integrity anchor, signed evidence, evidence retention and independent QA.
- [ ] Minimal authorized live model inference with separately checked correctness and reproducibility.
- [ ] Measurements: throughput, p95/p99 latency, error/denial rate, cancellation propagation, recovery time, and verified spend.
- [ ] Owner-approved security, legal/third-party-rights and production operational reviews. No real customer or financial actions before separate authorization.

## What is verified now

The repository contains a real, local, single-host file hashing worker; standard library HMAC reference transport; Ed25519-signed **synthetic** AI Passport, Guardian and Approval documents using a pinned Python cryptographic library; tests for the listed local attack cases; and documented GitHub Actions executions. This is not a secure general-purpose agent runtime, a live LLM, a real 24/7 cloud service, independent QA, a commercial cryptographic license issuer or an Enterprise certification.

Do not use founder artwork or the decorative cryptographic license seal to imply an independently valid access credential, production license server, legal ownership certificate or entitlement.

**Build software. Verify everything.**
