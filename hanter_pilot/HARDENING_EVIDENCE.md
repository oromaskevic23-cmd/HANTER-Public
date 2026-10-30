# HANTER Security Hardening — Encrypted Keys, Isolated NCA, Local LLM

**Engineering status:** E2/E3 public offline pilot and disposable GitHub Actions test infrastructure. **NOT** a deployed private command center, distributed production security service, or 24/7 server.  
**Owner / Final Architecture Authority:** Alexander Nikolaevich Romaskevich (RomaskevicH).  
**FREE_ONLY:** public standard GitHub Actions runner; no paid runners, persistent cloud services, paid APIs or token/financial actions. Never supply real private keys, customer data or passwords to CI.

## Tested layers and exact scope

| Component | Implemented | Verification | Limitations |
| --- | --- | --- | --- |
| HANTER route + authorized synthetic task | Local HMAC test permit, explicit tenant/orchestrator/NCA route, SQLite replay claim | Unit and offline functional tests | No authenticated network command channel; single-host SQLite only |
| AI Passport (prototype) | Ed25519 test-signed scoped identity and capability | Signatures and negative regressions | Temporary key fixtures; **not** a real Passport issuer |
| Guardian Core / Approval Gateway (prototypes) | Separate Ed25519 test-signed decisions, both matching Passport fingerprint | Positive/negative tests | No independent deployed approvals or signature of the Architect |
| Local Key Vault | AES-256-GCM at rest, Scrypt password KDF, owner-only 0700 folder / 0600 file, refuse overwrite | Decrypt/sign/verify, tampering, wrong password, permission tests | This is an **encrypted local test-key file**, not HSM/KMS, hardware isolation or robust multi-tenant secret service |
| Docker NCA isolated execution | One permitted synthetic file bind-mounted read-only, network=none, read-only image filesystem, UID/GID 65534, caps dropped, CPU/memory/pids/time limits | Actual Docker run + host QA in GitHub Actions | Temporary disposable container only; **not** hardened for arbitrary untrusted code, privileged host or production workloads |
| Ollama local model client | Exact allowlisted model, 127.0.0.1 endpoint, no proxy/redirect, bounded JSON response, model output cannot invoke tools | Contract tests with fake HTTP; real inference only if separate live job passes | No model weights or persistent inference server shipped in Git repo |
| Local audit | SQLite SHA-256 hash chain | Integrity and modification tests | Not a signed externally anchored Audit Ledger |
| QA | Separate in-process SHA-256 check | Real file digest compared on host | Not independently operated QA/security certification |

## Reproduce core checks

Python 3.11+ (Linux or compatible environment) and Docker for isolated-container execution:

    python3 -m pip install -r hanter_pilot/requirements-pilot.txt
    python3 -m unittest discover -s tests -p 'test_*.py' -v
    python3 -m hanter_pilot.signed_demo
    python3 -m hanter_pilot.key_vault

Only after pre-pulling and separately approving the Docker image:

    docker pull python:3.12-slim
    python3 -m hanter_pilot.isolated_worker

Docker uses \`--pull=never\` during worker execution. If Docker is missing, policy denies rather than falling back to unisolated execution. Production must pin a vetted container digest and implement actual kernel isolation/independent security QA.

## Actual local model probe (optional, never automatic on a server)

The [Ollama one-time evidence workflow](../.github/workflows/hanter-one-time-local-llm.yml) is a limited experiment on an ephemeral standard GitHub-hosted public runner. It verifies the Ollama release archive SHA-256 before extraction and runs an explicitly allowlisted small, third-party CPU model. The initial one-time pull-request run was verified at [GitHub Actions run #41142037544](https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41142037544). Subsequent execution is **manual-only** via workflow_dispatch; it is not a background monitor or 24/7 service.

To test on an authorized local machine with Ollama running **only on 127.0.0.1** and the approved model already available:

    HANTER_LOCAL_LLM_PROBE=I_ACCEPT_LOCAL_INFERENCE python3 -m hanter_pilot.ollama_local

The adapter sends **synthetic prompt text only**, disables streaming and unloads the model after response. It disables proxies and redirects, checks JSON response shape and refuses a different model. No model output is treated as a trusted order, executable code, approval or quality proof. This is not VELION model training or deployment: it uses an explicitly identified **third-party SmolLM2** checkpoint for connectivity evidence.

For actual production, HANTER must use a separately protected inference service, measure quality on independently authored tasks, and explicitly bind any model call to an approved Enterprise Skill and signed task envelope.

## Governed model proposal — verified synthetic integration

The [signed proposal gate](governed_model.py) now accepts a narrowly scoped **LLM_PROPOSAL** capability. It binds the exact prompt SHA-256 into the signed Passport resource field, requires separate Guardian and Approval decisions signed over that Passport, checks tenant/orchestrator/NCA, revocations, zero cost and the Owner Kill Switch, then reserves the task in the SQLite replay guard *before* contacting loopback-only Ollama. The generated response is recorded only as an **untrusted proposal**, not as an executable order.

- [Verified one-time signed-LLM execution](https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41142037544): real SmolLM2 inference, 264-character response in governed run, Ed25519 test Passport and two distinct test decision signatures, local audit-chain check.
- [Verified unit tests and Docker isolation](https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41142099183): 109/109 test cases plus actual no-network Docker execution.
- These represent a **disposable CI reference**, not a persistent NCA runtime or real independent Guardian Core/Approval Gateway/Owner signing authority.
- Actual worker isolation and actual model inference were verified as separate stages. The Ollama process is not run inside the no-network Docker container, and the model has **no execution/tool privileges**.
- Replay guard is local SQLite only; future deployments require authenticated services, durable distributed leases, signed independent audit anchors and production-ready key custody.

## Next security gates — NOT met by unit tests

1. Protected real issuer/trust anchors with external KMS/HSM, key rotation and auditable issuance, plus signer separation and signed revocation feed with rollback resistance.
2. Real and independently authenticated Guardian Core, Approval Gateway and AI Passport services; enforce Owner Kill Switch across all live workers and prove propagation latency.
3. Durable distributed idempotency, queue leases, tenant isolation and recovery; no bypass due to process restart or network failure.
4. Trusted immutable content snapshots and secure OS file access, provenance of container images and model weights, adversarial prompt-injection tests.
5. Isolated, separately operated QA, anchored ProofGraph / Audit Ledger with operational evidence.
6. Only after explicit Owner approval: a single minimal private server-side worker, followed by load and safety tests. No autonomous payments, transactions, token exchange actions, third-party publication or unapproved spending.

Preserve canonical **Federated Multi-Orchestrator Architecture**: Architect → HANTER → scoped independent domain orchestrators → professional NCA teams → least-privilege execution. **ORION** provides collective intelligence but not execution authorization. AI Passport, Enterprise Skills, Guardian Core, Approval Gateway, Audit Ledger, Zero Trust, Public/Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary are non-negotiable.

The long-term one-billion-plus NCA design is a **registry capacity target**, not proven active fleet scale. Existing repository LICENSE, provenance and historical contribution records are not modified.

**Build software. Verify everything.**
