<p align="center">
  <img src="assets/hanter-banner-original-20261029.jpg" alt="HANTER — Chief Executive Orchestrator, Nano Core Agents and IMPERIAL Core" width="100%" />
</p>

# HANTER — Public Architecture

**Project creator / founding architect:** Alexander Nikolaevich Romaskevich (RomaskevicH). [Authorship](AUTHORS.md) · [License inventory](governance/LICENSE_INVENTORY.md).


Public mission-coordination and Architect-interface design. Domain orchestrators retain bounded responsibilities.

**Status: SPECIFIED architecture plus TESTED offline executable reference on main; no deployed autonomous service.**  
Evidence checkpoint: **31 October 2026** (linked test executions apply only to the stated commit revisions).

## Founder and architectural authority

**Alexander Romaskevich — RomaskevicH**  
Founder • Owner • CEO of IMPERIAL Core  
Architect / Final Architectural Decision Authority

**HANTER — AI Command Center / Chief Systems** operates under the founder's architectural decisions. This role does not imply a single unrestricted global orchestrator.

## Offline engineering pilot — executable reference (not production)

[HANTER → federated orchestrator → NCA handoff pilot](hanter_pilot/README.md) provides a reproducible, **read-only local file-hashing task** under a short-lived HMAC test permit, scoped federation route, SQLite replay claim, in-process QA and local hash-chained evidence. It does not activate production NCA, provide a real AI Passport, connect to a model, establish a secure sandbox or run continuously.

Run: `python3 -m unittest discover -s tests -p 'test_hanter_pilot.py' -v` and `python3 -m hanter_pilot.pilot`. The CI workflow verifies the scoped pilot on pull requests and on pushes to main; the Ollama inference workflow remains manual-only. Older public documentation remains applicable to the architecture; a tested local demo is **not** proof of a deployed autonomous command center.

## Signed sandbox workflow — AI Passport × Guardian Core × Approval Gateway

The [Ed25519 signed-authority reference](hanter_pilot/ED25519_PASSPORT.md) extends the offline pilot with separate, cryptographically verified demo documents for AI Passport, Guardian and Approval, plus simulated revocation and Owner Kill Switch enforcement. Its [executable demo](hanter_pilot/signed_demo.py) uses temporary local keys and performs one genuine read-only NCA task with QA and a local evidence chain.

These are **non-production local fixtures** and do not constitute actual deployed AI Passport issuance, live Guardian Core / Approval Gateway, independent external QA, trusted Owner approval, autonomous LLM inference or 24/7 server-side availability. No real execution authority is granted by GitHub code or CI results.

## Verified engineering checkpoint — local NCA, isolation and governed LLM

The [hardening and evidence register](hanter_pilot/HARDENING_EVIDENCE.md) describes an **encrypted owner-only local test-key vault**, a **real network-disabled, read-only Docker NCA worker**, and a **real CPU inference pilot** with third-party SmolLM2 under ephemeral Ed25519 test Passport, Guardian and Approval signatures. Model output is a non-executable proposal and is recorded in a local SQLite evidence chain.

- [109/109 unit tests and real Docker job — GitHub Actions](https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41142099183).
- [One genuine signed-authority NCA → Ollama call — GitHub Actions](https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41142037544).
- Actual Ollama smoke tests are **manual-only after the verified initial run**; no GitHub scheduled monitoring.
- These experiments run on **disposable GitHub Actions infrastructure**, not an IMPERIAL Core 24/7 production server. No real Owner-signed production AI Passport, authenticated Guardian Core / Approval Gateway service, externally anchored Audit Ledger, independently operated QA or autonomous revenue process is claimed.

## Public technical evidence

The public main branch includes executable offline Python reference code and reproducible GitHub Actions evidence. These checks cover synthetic tasks, signed test permits, local model proposals and a disposable Docker worker; they do **not** establish a 24/7 production runtime, independently deployed approval services or billion-agent capacity.

## CI and change-control policy

The [CI and Release Gate](governance/CI_RELEASE_GATE.md) records the mandatory pre-merge checks, their scope and code-ownership boundaries. Every pull request and every push to main must run the HANTER offline test suite and a disposable read-only Docker task. Results apply **only to the tested commit SHA**. Historical failed checks are retained as truthful evidence and must not be erased by force-pushing published history. The real-model Ollama evidence workflow is **manual-only**, not continuous monitoring. CODEOWNERS entries alone do not enforce required approval without a configured GitHub branch ruleset.

## Architecture and governance

Preserve the Federated Multi-Orchestrator Architecture, multiple organizational structures, professional teams and dynamic Nano Core Agents. AI Passport, Enterprise Skills, Guardian Core, Approval Gateway and Audit Ledger remain architectural requirements. Identity ≠ Authority; Capability ≠ Approval. Zero Trust, Deny by Default and Fail Closed apply across the Public / Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary.

## Documentation and continuity

- [Current ecosystem architecture](https://github.com/oromaskevic23-cmd/Capital-Core-Public/blob/main/ARCHITECTURE.md).
- [Founder identity and architectural authority](https://github.com/oromaskevic23-cmd/oromaskevic23-cmd#founder-introduction).
- [Public portfolio and status definitions](https://github.com/oromaskevic23-cmd/Capital-Core-Public/blob/main/docs/PORTFOLIO.md).
- [Verified milestones](https://github.com/oromaskevic23-cmd/Capital-Core-Public/blob/main/docs/EVIDENCE.md) and [engineering roadmap](https://github.com/oromaskevic23-cmd/Capital-Core-Public/blob/main/ROADMAP.md).
- [Historical public specification notes](https://github.com/oromaskevic23-cmd/HANTER-Public/blob/49e71d21a8588991af39354e9d765366e4d06e51/README.md) — retained in Git history; earlier role wording is superseded and design narratives do not establish runtime operation.

## Collaboration, security and attribution

Start non-confidential collaboration through the [founder profile](https://github.com/oromaskevic23-cmd). Follow the [responsible-disclosure guidance](https://github.com/oromaskevic23-cmd/Capital-Core-Public/blob/main/SECURITY.md) before sharing sensitive security information. Contributions should cite revisions, meaningful tests and limitations.

**Authorship: Alexander Romaskevich — RomaskevicH.** Third-party rights, existing notices and licenses remain unchanged. Public visibility does not grant an additional license. No private source or private test logs are imported here.

**Build software. Verify everything.**

## Browser integration — evidence boundary

A bounded Playwright MCP browser-integration experiment was reported in a restricted engineering repository. The underlying source and CI run are not publicly accessible, so they are not claimed as independently verified public evidence. This public architecture repository remains documentation-only. Browser automation alone does not establish authenticated GitHub sessions, continuous execution, or independent NCA authority. No monitoring is scheduled.


---

### Canonical founder and public project identity

This public repository is part of the [IMPERIAL Core source portfolio maintained by Alexander Nikolaevich Romaskevich (RomaskevicH)](https://oromaskevic23-cmd.github.io/oromaskevic23-cmd/projects/), Founder, Owner and CEO of IMPERIAL Core and its final architectural decision authority. See the [canonical public project registry](https://oromaskevic23-cmd.github.io/Capital-Core-Public/reference/projects/) and original commit/contributor history for evidence and provenance. This reference does **not** imply exclusive rights in third-party models, libraries, trademarks or other contributors' work, or certify live production status. Project-specific licensing and security restrictions remain unchanged.
