# HANTER × Google Search Console — Dual-Signature Approval Contract

**Architect / Final Architectural Decision Authority:** Alexander Nikolaevich Romaskevich (RomaskevicH).  
**Checkpoint:** 2026-11-04 · **Status:** TESTED SOURCE INTEGRATION; no production owner identity or Google OAuth connected.

## What is implemented

HANTER now contains a domain-separated Ed25519 approval **verifier** for Google Search Console sitemap submission. This is a verification component, not a signing authority, OAuth identity provider, live worker or tool that submits websites to Google.

- [Verification code](../hanter_pilot/gsc_approval_verifier.py): `SignedSubmissionProofs`, `TrustRoot` and role-separated `owner(...)` / `qa(...)` callbacks
- [Twelve adversarial tests](../tests/test_gsc_approval_verifier.py): key separation, issuer identity, signer identity, audience, scope binding, replay attempt via altered operation, forged signature, expired permit, revoked reference and stale revocation snapshot
- [Real cross-repository integration test](../tools/gsc_signed_submit_contract.py): verified signatures flow into `SubmissionGate` in IMPERIAL-Plugins with synthetic Google responses, without contacting Google or disclosing Owner keys
- [CI gate](../.github/workflows/gsc-signed-approval-contract.yml): Python 3.11/3.12, immutable Plugin commit and synthetic provider test

**Latest pinned-plugin cross-repository evidence:** https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41731805301 (IMPERIAL-Plugins immutable revision `6c94513b64812a6a27d78b238fb1afa3105c25a5`, Python 3.11/3.12, Ed25519 and simulated Google PUT all PASS). **Original test run:** https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41731058389 — both Python versions passed 12/12 cryptographic tests and the HANTER→Plugins integration test.

## Canonical authority model

```text
Architect (Owner; final architectural authority)
  → HANTER (AI Command Center; authority coordination)
      → Federated SEO / Publishing Orchestrator (separate trust domain)
          → AI Passport + Enterprise Skills + Guardian Core
          → Separate Owner and Independent QA signed evidence
          → Approval Gateway (this verifier is a source-level component)
          → Public site HTTP/sitemap/canonical audit
          → Separate IMPERIAL-Plugins SubmissionGate (private host)
          → Google OAuth + Search Console API (NOT CONNECTED)
          → Audit Ledger / reconciliation / independently reported index evidence
```

HANTER is not a single global execution orchestrator. The private GSC writer cannot be discovered through the four **read-only** public MCP tools. The publisher has no authority over unrelated Google accounts, companies, private repositories, property URLs or financial assets. No NCA, even a universal agent, may forge Owner approval.

## How proof binding works

The verifier checks an **externally obtained** canonical `SitemapIntent` against two signatures from **different pinned Ed25519 public keys**. Each proof signs:

- Evidence schema and audience (`imperial-gsc-sitemaps-submit`)
- Specific Owner / QA role, trusted issuer and key ID
- `proof_ref`, signer identity and a positive, bounded validity window
- SHA-256 of the **exact** submission intent, site ID and operation ID
- Approved effect limited to `GOOGLE_SITEMAP_SUBMIT_ONLY`

Both proofs must be valid, come from independently identified signers, match the same canonical intent and not occur in a fresh trusted revocation set. Reusing the proof against a different site, operation or policy fails.

**Important:** Verifying that two *cryptographic keys differ* is not equivalent to proving that two real independent humans signed; a production trust-root registry needs externally attested real identities, revocation governance and secure storage. The current test suite generates disposable keys solely for unit tests.

## Owner-controlled production requirements

1. Independently establish Owner identity and pinned Owner Ed25519 public root using a separate authorized process; the program must never accept a trust root supplied by the NCA or untrusted MCP prompt.
2. Provision an **independent QA** signing key and identity with different human ownership, approved roles and external revocation feeds.
3. Store signed proof documents and revocation snapshots outside this public repository in a secure private service.
4. Keep OAuth tokens only inside a properly authorized, encrypted private runtime. Google Contacts/Gmail login is not Search Console API consent.
5. Enforce Guardian Core / AI Passport / Enterprise Skills and Approval Gateway on the same exact tenant, orchestrator, site, operation and policy version.
6. Run the public site audit, reconcile Google sitemaps, store signed provider receipts and independently verify Google URL Inspection.
7. Separately anchor production Audit Ledger events in immutable external storage and conduct incident-response and recovery drills.
8. Keep Owner Kill Switch fail-closed. Never retry a timed-out Google submission automatically, and never equate Search Console sitemap registration to indexed pages.

## Evidence levels

| State | Current |
|---|---|
| Real Ed25519 signature verification code | IMPLEMENTED / CI PASS |
| Cross-repo trusted callback to Google submission gate | SYNTHETIC INTEGRATION / PASS |
| Real Owner Ed25519 identity enrollment | NOT VERIFIED |
| Independent, externally attested QA authority | NOT VERIFIED |
| Google OAuth grant and verified property | NOT CONNECTED |
| Google `sitemaps.submit` call with genuine HTTP receipt | NOT EXECUTED |
| Google URL Inspection / indexed pages | NOT VERIFIED |

Source tests must never be presented as live production authorization.

**Relevant official Google references:**
- https://developers.google.com/webmaster-tools/v1/how-tos/authorizing
- https://developers.google.com/webmaster-tools/v1/sitemaps/submit
- https://developers.google.com/webmaster-tools/v1/sites/list

**Architecture → Implementation → Evidence**.
