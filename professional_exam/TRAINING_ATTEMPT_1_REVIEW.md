# HANTER Professional NCA — Attempt 1 Postmortem

**Date:** 2026-11-01. **Agent identity in first 100:** `IMPERIAL-JOHNNY-WALKER-001` (registered wave 1, slot 36, CODE_ENGINEERING); **not yet a live permanently deployed worker**.

- CI run: https://github.com/oromaskevic23-cmd/HANTER-Public/actions/runs/41254823947
- Model: third-party `qwen2.5-coder:0.5b` locally downloaded onto an ephemeral GitHub Actions runner.
- HANTER: verified three synthetic role-separated Ed25519 permits; 14/14 adversarial authorization tests passed.
- VELION v2: 32/32 deterministic route-contract tests passed.
- Model inference: REAL, generated `candidate.mjs`, SHA-256 `6205f413b25908cec16f11b3a4a1ff61fcd258a7872cf72d0a12eab8a2c7ad48`.
- Second-job QA: **FAIL**; missing `export` and reversed bounding formula `Math.min(lower, Math.max(value, upper))`.
- Result: no professional certification, no production worker, no money, no external effects, no paid calls.

## Remediation

Retrain on explicitly written requirements and examples, enlarge model to Qwen2.5-Coder 1.5B; preserve hidden independent 24-case oracle unmodified. Repeat real model execution and independent sandbox review. Promote only if independently verified. No retroactive PASS for failed attempts.
