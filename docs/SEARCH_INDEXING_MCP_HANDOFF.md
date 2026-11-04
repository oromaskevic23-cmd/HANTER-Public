# HANTER × IMPERIAL Search Indexing MCP — Federated Integration Contract

**Date:** 2026-11-03  
**Founder / Architect / Final Architectural Decision Authority:** Alexander Nikolaevich Romaskevich (RomaskevicH).  
**Classification:** E1 — reproducible, pinned **source-level stdio integration test**. No HANTER production orchestration, Google Search Console access, autonomous NCA fleet, or live Google indexing is implied.

## Architectural authority and boundaries

```text
Architect / Final Architectural Decision Authority
  |
HANTER (AI Command Center — mission intent and proof)
  |
Federated SEO / Publishing Orchestrator (proposed private runtime)
  |   AI Passport -> Enterprise Skills -> Guardian Core
  |   -> Approval Gateway -> Independent QA -> Audit Ledger
  |
IMPERIAL Search Indexing MCP (public read-only stdio reference)
  |-- indexed-source inventory (23 public project repositories)
  |-- public website sitemap/robots/canonical/JSON-LD verification
  |-- Google Search Console property/sitemap read connector (not OAuth-connected)
  |
Google write permissions (NOT ALLOWED at this integration stage)
```

This preserves the canonical **Federated Multi-Orchestrator Architecture**, rather than treating HANTER or the MCP server as a single universal execution orchestrator. The existing HANTER public pilots remain separate. No private credentials or customer information are copied into this public repository.

## Reviewed source dependency

- Remote source: https://github.com/oromaskevic23-cmd/IMPERIAL-Plugins
- **Immutable integration reference:** `6c23d839b85bf7ddc80aa9f1df7b2a4ed8328c60`
- MCP local launcher: `tools/search_indexing_mcp.py`
- MCP server: `src/imperial_plugins/indexing_mcp.py`
- Google-only adapter source: `src/imperial_plugins/search_console_read.py`
- Original documentation: https://github.com/oromaskevic23-cmd/IMPERIAL-Plugins/blob/main/docs/SEARCH_INDEXING_MCP.md

The dependency is checked out from the same verified public owner using a pinned commit SHA, never a floating branch during CI. Existing third-party licenses and Git contributor history are unaffected.

## Executed cross-repository contract

The added `.github/workflows/indexing-mcp-contract.yml`:

1. Uses read-only GitHub Actions `contents: read` permission and a pinned checkout action.
2. Checks out HANTER and exactly the reviewed IMPERIAL-Plugins commit.
3. Launches a real local Python MCP stdio subprocess (no HTTP listener and no credential).
4. Exchanges JSON-RPC `initialize`, `tools/list` and two `tools/call` requests, then parses the actual response.
5. Requires exactly four available read-only tools, 23 public technical projects, both Search Console property plans, and explicit `UNVERIFIED` Google indexing status.
6. Fails the build on protocol errors, changed public project list count or any assertion that a Google submission was performed.
7. Verifies that the newer default-deny `SubmissionGate` cannot initiate an external Google write without actual Owner permission. No trusted issuer, real Google OAuth token, approved write intent or provider request exists in the test. The new gate remains protected by independent QA, owner approval verification, private property permission checks and a persistent local replay/incident journal.

**Latest pinned test result (2026-11-04):** HANTER GitHub Actions PASS. The workflow launches the locally pinned MCP process and separately proves that the new Google sitemap SubmissionGate refuses to proceed while Owner Kill Switch is active. Both checks run without Google credentials or external sitemap PUT.

This is **integration contract evidence**, not a live signed NCA handoff. To become a production HANTER execution path, the following remain necessary:

- Real Owner Ed25519 enrollment and protected key custody.
- Genuine time-limited AI Passport and approved Enterprise Skills, bound to tenant, orchestrator, mission and runtime domain.
- Guardian Core policy, Owner Kill Switch and Approval Gateway for every proposed Google mutation.
- A separate independent human QA of source and website claims.
- Append-only durable Audit Ledger and authenticated, replay-resistant cross-service messaging.
- OAuth connection to actual Google Search Console properties in a **private** runtime (Google Contacts is insufficient).
- An owner-approved `sitemaps.submit` flow with a provider-issued receipt, followed by independently inspected Google indexing results.

## Signed Owner / independent QA cryptographic verification

The additional [Ed25519 signed approval contract](GSC_SIGNED_APPROVAL_HANDOFF.md) was tested against a pinned IMPERIAL-Plugins `SubmissionGate`. The source verifies separate approved signers and a domain- and operation-bound permit using independently pinned public keys. This does not imply production Owner enrollment, actual OAuth, live NCA execution or a submitted sitemap. [Passing cross-repo proof](https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41731805301).

## Google Search Console evidence tiers

| Tier | Meaning | Current state |
|---|---|---|
| E1 | Public source and reproducible MCP stdio contract | Implemented; see exact CI result |
| E2 | Actual owner OAuth / property access | NOT VERIFIED |
| E3 | Google accepted a sitemap submission | NOT VERIFIED |
| E4 | Google URL Inspection returned an index report | NOT VERIFIED |
| E5 | Observed search visibility and performance trend | NOT VERIFIED |

A passing MCP protocol test or valid sitemap is not evidence of Google crawling, ranking, production worker activation or revenue. There is no automated Google sitemap submission in the public MCP.

## Runtime safety

FREE_ONLY; Zero Trust, deny by default, explicit public/private boundary, retained founder source attribution, no wallet access, no financial flows. The CRYPTO IMPERIAL Ecosystem Boundary remains independent. IMPERIUM is a long-term architectural digital currency envisioned for AI agents worldwide, not an established globally adopted currency.

**Reproduce:** open the workflow file and run via GitHub Actions `workflow_dispatch`, or inspect the run for the exact commit. No owner keys are required for the public integration test.

Architecture → Implementation → Evidence.

## 2026-11-04 verified discoverability upgrade

HANTER's immutable MCP dependency is now the reviewed IMPERIAL-Plugins revision `6c23d839b85bf7ddc80aa9f1df7b2a4ed8328c60`. New public, non-privileged verification capabilities include:

- Authenticated owner reconciliation: **32 owner repositories**, split **25 public / 7 private**; public API and independently reviewed metadata verify **23 public technology projects** plus two other public repositories. Private names are **not** emitted into public CI.
- Public-only fail-closed GitHub API guard: rejects unforeseen project visibility drift rather than silently publishing new project names.
- Correct Googlebot scope of `robots.txt`: the effective file is at the **host root**. The measured host-root URL returned HTTP 404, so nested GitHub Pages project-path robots files do not govern crawler behavior.
- Bounded **14-case SEO-NCA practice examiner**, with a 90% minimum, zero critical safety violations, and explicit non-certification: no real model training, independent QA, passport, commercial permissions or Google indexing is granted.
- Evidence: [Founder source/HTTP audit](https://github.com/oromaskevic23-cmd/oromaskevic23-cmd/actions/runs/41750707801) and [Public inventory, root robots and SEO-NCA tests](https://github.com/oromaskevic23-cmd/IMPERIAL-Plugins/actions/runs/41751283283).

This source-level contract **does not** deploy a HANTER worker or connect real Search Console OAuth. Privileged Google writes still require explicit Owner and independent QA approval under Guardian Core / Approval Gateway / Audit Ledger, and verified external provider receipts.
