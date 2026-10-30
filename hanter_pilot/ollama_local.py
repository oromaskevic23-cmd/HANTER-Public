"""Loopback-only Ollama inference adapter: output is DATA, never an executable tool call.

An actual model must be locally installed and explicitly started by the owner.
No model is downloaded, no cloud endpoint is contacted, and no LLM permission
can change a worker's Guardian/Approval/Enterprise Skills boundaries.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request

from .pilot import Denied

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
ALLOWED_MODEL = "smollm2:135m-instruct-q4_K_M"
MAX_RESPONSE_BYTES = 16_384
MAX_PROMPT_CHARS = 2_000
MAX_OUTPUT_CHARS = 3_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def model_proposal(prompt: str, *, model: str = ALLOWED_MODEL,
                   http_open=None) -> dict:
    """Receive an untrusted local inference proposal; never execute its text."""
    if model != ALLOWED_MODEL:
        raise Denied("UNAPPROVED_MODEL")
    if (type(prompt) is not str or not 0 < len(prompt) <= MAX_PROMPT_CHARS
            or "\x00" in prompt):
        raise Denied("BAD_PROMPT")
    payload = {
        "model": model,
        "prompt": prompt,
        "system": ("Answer in concise English. This is a synthetic sandbox task. "
                   "Do not claim you have taken actions or accessed external systems."),
        "stream": False,
        "keep_alive": 0,
        "options": {"temperature": 0, "num_predict": 96},
    }
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        OLLAMA_URL,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    # No proxies and no redirects: an LLM request must never leave loopback.
    opener = http_open if http_open is not None else urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    ).open
    try:
        with opener(request, timeout=90) as response:
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                raise Denied("UNEXPECTED_LLM_CONTENT_TYPE")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, TimeoutError, urllib.error.URLError):
        raise Denied("LOCAL_LLM_UNAVAILABLE") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise Denied("LLM_RESPONSE_TOO_LARGE")
    try:
        parsed = json.loads(raw)
        text = parsed["response"]
        if (not isinstance(text, str) or not 0 < len(text) <= MAX_OUTPUT_CHARS
                or parsed.get("done") is not True or parsed.get("model") != model):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise Denied("INVALID_LLM_RESPONSE") from None
    return {
        "model": model,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "response_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "response": text,
        "qa": "RESPONSE_SHAPE_ONLY_NOT_SEMANTIC_QA",
        "allow_tools": False,
        "execution_authority": False,
        "external_effects": 0,
        "production_authorized": False,
    }


def main() -> None:
    if os.environ.get("HANTER_LOCAL_LLM_PROBE") != "I_ACCEPT_LOCAL_INFERENCE":
        raise SystemExit(
            "Local inference is disabled. To run explicitly, start Ollama on "
            "127.0.0.1:11434 with the allowlisted model and set "
            "HANTER_LOCAL_LLM_PROBE=I_ACCEPT_LOCAL_INFERENCE."
        )
    prompt = (
        "In one sentence, describe why a worker must wait for permission "
        "before reading an authorized test file."
    )
    result = model_proposal(prompt)
    # Model words are untrusted data. Print only an evidence digest by default.
    evidence = {k: v for k, v in result.items() if k != "response"}
    evidence["response_characters"] = len(result["response"])
    evidence["local_model_call_completed"] = True
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
