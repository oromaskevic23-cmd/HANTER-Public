# HANTER — CI and Evidence Release Gate

**Status:** Repository policy and automated CI checks, **not** a certificate of deployment or a guarantee that GitHub branch rulesets are active.  
**Architect / Final Architectural Decision Authority:** Alexander Nikolaevich Romaskevich (RomaskevicH).  
**Applies to:** HANTER-Public main branch, future pull requests and synthetic offline test workloads.

## 1. Required release sequence

1. Work on a reviewed feature branch, preserve attribution, third-party notices, and original licensing.
2. Run the **HANTER offline authorized NCA handoff pilot** on every pull request, not only selected paths: syntax compilation, Python test discovery, Ed25519-signed local demo, sealed test-key vault, Docker no-network worker, and host-side digest comparison.
3. Run **English documentation**, **Founder attribution integrity**, and **IMPERIAL Founder Authorship and License Guard** where applicable.
4. Merge only after the checks for the **exact reviewed head SHA** show SUCCESS. Use a single squash commit for new scoped changes where appropriate; do not rewrite merged history.
5. Run the offline test suite again on **every push to main**. A successful PR run is not a substitute for main-branch evidence.
6. Retain GitHub Actions URLs and exact commit SHAs; never report a green run against another revision as proof of the current code.
7. Do not enable paid infrastructure, production credentials, customer/financial tasks or persistent agents through this repository.

## 2. Green checks vs historical failures

Earlier PR #9 commits had failures in the signed-permit regression test because the updated guard returned `BAD_DOCUMENT_SCHEMA` while the old test expected `POLICY_HOLD`. Both are deny decisions; the exact-code assertion was repaired in commit `1b1ac290`. This does **not** erase those historical failed attempts. The final PR #9 revision `6ea851341` passed four GitHub Actions workflows and was merged into main as `0a056336f`.

**Never rewrite the merged commit ancestry solely to hide past failed test runs.** GitHub displays historical statuses on their original commits; that is normal, auditable evidence. Only the latest reviewed commit checks establish current test status.

## 3. Checks and limits

| Check | What PASS establishes | What it does not establish |
| --- | --- | --- |
| Offline Python suite | Named regression cases on a specific revision | Formal proof of all security properties |
| Signed test Passport, Guardian, Approval | Ed25519 verification using ephemeral local test authorities | Live authorization, real Owner signature or HSM custody |
| Key vault demo | Sealed local test keys and filesystem permissions | Enterprise KMS, remote issuer, distributed revocation |
| Docker worker | One real bounded no-network read-only job in disposable CI | Production sandbox for arbitrary untrusted code |
| Ollama evidence | One actual local third-party small-model call | Continuously running LLM/NCA or validated model reasoning |
| English docs and founder license checks | These concrete static workflow assertions | Legal verification or independent Enterprise certification |

The real Ollama workflow remains **manual-only**; there is no scheduled model download or agent-monitoring task. The stable CI workflow is separate from the optional model evidence run.

## 4. Permissions and protection

The expanded `CODEOWNERS` file identifies the founder as review owner for HANTER source, tests, workflows and release policy. **CODEOWNERS alone does not mandate approval.** A GitHub branch protection rule or ruleset must independently require reviews and the named checks, restrict force pushes and deletion, and apply to the main branch. Until such a rule is confirmed through GitHub settings/API, enforcement is **not verified**.

## 5. Remaining production gates

**Architecture → Implementation → Evidence:** protected real AI Passport issuers, independent Guardian Core and Approval Gateway services, enforceable Enterprise Skills, durable Audit Ledger, ProofGraph, IntentLock, Owner Kill Switch and Zero Trust boundaries; isolated worker and browser lifecycles; externally trusted audit anchoring; independent QA; verified tenant boundaries. Preserve Public / Private and CRYPTO IMPERIAL Ecosystem Boundaries and the Federated Multi-Orchestrator Architecture (HANTER + many domain orchestrators + professional NCA teams). ORION synthesizes collective intelligence without bypassing authorization.

The future 1,000,000,000+ registered-agent design is a long-term logical capacity target, **not** a present runtime claim.

**Build software. Verify everything.**
