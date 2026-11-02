# HANTER x IMPERIAL Skill - First Federated Sub-NCA Task

Date: 2 November 2026.
Original founder and architect: Alexander Nikolaevich Romaskevich (RomaskevicH).
Scope: one real local synthetic file-hash job under signed TEST permits, not activated professional agents.

## Architecture and evidence

HANTER checks the original IMPERIAL-Skill source pinned to commit 3ae7ccc86d5e0329723ae3beb5a79ea22cdc3861. It verifies the manifest, offline exam hash, federated tenant/orchestrator domain and deterministic 100-subagent plan. A single experimental NCA-SUB-001 is selected for a disposable run. The other 99 records stay planned only; the Skill dispatches zero jobs.

The test builds a synthetic source with hashes of the fleet plan and first task. HANTER's existing signed-demo gate checks three separately signed Ed25519 TEST documents (Passport, Guardian, Approval); its HMAC local worker computes a real SHA-256 of the file. Locally authored QA reopens the file and rehashes it, while a separate Python process independently recomputes synthetic content and validates the non-secret receipt. SQLite replay and local hash-chain checks use the existing HANTER pilot.

All private signing keys exist in memory during the test only. They are NOT genuine Owner enrollment or an issued production AI Passport. Neither local QA checker constitutes externally independent QA. The job runs local host code in an ephemeral GitHub Actions runner, NOT a hardened long-lived container or deployed service. Nothing here establishes real 100-agent concurrency, VELION inference, 24/7 server availability, customer operations or commercial permissions.

## Verification

The separate skill100-first-job.yml workflow verifies the exact pinned Skill Git SHA, runs adversarial test suites with Python 3.11 and 3.12, performs one local signed test, independently checks the synthetic receipt in a second process, and denies any true production claim. No GitHub Actions secret or paid API is needed.

From the root of HANTER with the pinned Skill checkout in pinned-skill and the existing Ed25519 dependency installed:

PYTHONPATH="$PWD/pinned-skill/src:$PWD" python -m unittest discover -s tools -p test_skill100_bridge.py -v

PYTHONPATH="$PWD/pinned-skill/src:$PWD" python -m hanter_pilot.skill100_bridge --skill-root pinned-skill --output /tmp/skill100-receipt.json

PYTHONPATH="$PWD/pinned-skill/src:$PWD" python tools/verify_skill100_receipt.py --skill-root pinned-skill --receipt /tmp/skill100-receipt.json

## Mandatory future production gates

1. Out-of-band Owner Ed25519 root enrollment, secret custody, revocation, evidence.
2. Real per-worker revocable AI Passport and Enterprise Skills, actual Guardian Core and Approval Gateway, full task and tenant binding.
3. Hardened separate worker sandbox; process Kill Switch, tested rollback and recovery.
4. Independent QA operated outside the worker trust domain; protected ProofGraph and Audit Ledger with external anchoring.
5. HANTER command channel with authenticated federated orchestrators, durable task queue, idempotency, leases, retry, observability.
6. One signed successful production worker before attempting 10 or 100 certified worker slots.

Preserve Architecture Before Implementation; Zero Trust, FREE_ONLY, Owner Kill Switch, Public/Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary. VELION is the model fabric and MAX is one mode. ORION is advisory, not a global orchestrator.

This document describes an integration pilot, not 100 running NCA workers.
