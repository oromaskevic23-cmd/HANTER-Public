"""Offline tests; fake HTTP is not evidence of any actual LLM inference."""

import json
import unittest
from urllib.error import URLError

from hanter_pilot.ollama_local import (
    ALLOWED_MODEL, OLLAMA_URL, model_proposal,
)
from hanter_pilot.pilot import Denied


class FakeResponse:
    def __init__(self, data, mime="application/json"):
        self.data = data
        self.headers = {"Content-Type": mime}

    def read(self, limit):
        return self.data[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class LocalModelAdapterTests(unittest.TestCase):
    def setUp(self):
        self.last_req = None

    def opener(self, req, **kwargs):
        self.last_req = req
        self.assertEqual(req.full_url, OLLAMA_URL)
        self.assertTrue(req.full_url.startswith("http://127.0.0.1:"))
        data = json.loads(req.data)
        self.assertFalse(data["stream"])
        self.assertEqual(data["keep_alive"], 0)
        self.assertEqual(data["model"], ALLOWED_MODEL)
        return FakeResponse(json.dumps({
            "model": ALLOWED_MODEL, "response": "Authorization precedes file access.",
            "done": True
        }).encode())

    def test_loopback_proposal_is_data_not_an_action(self):
        result = model_proposal("Explain permissions.", http_open=self.opener)
        self.assertEqual(result["response"], "Authorization precedes file access.")
        self.assertFalse(result["allow_tools"])
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["production_authorized"])
        self.assertEqual(result["external_effects"], 0)
        self.assertEqual(result["qa"], "RESPONSE_SHAPE_ONLY_NOT_SEMANTIC_QA")

    def test_unapproved_model_denied_before_io(self):
        with self.assertRaises(Denied) as e:
            model_proposal("test", model="evil:latest", http_open=self.opener)
        self.assertEqual(e.exception.code, "UNAPPROVED_MODEL")
        self.assertIsNone(self.last_req)

    def test_blank_prompt_denied(self):
        with self.assertRaises(Denied):
            model_proposal("", http_open=self.opener)

    def test_large_prompt_denied(self):
        with self.assertRaises(Denied):
            model_proposal("x" * 2001, http_open=self.opener)

    def test_nonjson_denied(self):
        with self.assertRaises(Denied) as e:
            model_proposal("test", http_open=lambda req, **kw: FakeResponse(b"not-json"))
        self.assertEqual(e.exception.code, "INVALID_LLM_RESPONSE")

    def test_wrong_mime_denied(self):
        with self.assertRaises(Denied) as e:
            model_proposal("test", http_open=lambda req, **kw: FakeResponse(b"hi", "text/html"))
        self.assertEqual(e.exception.code, "UNEXPECTED_LLM_CONTENT_TYPE")

    def test_unfinished_response_denied(self):
        body = json.dumps({"model": ALLOWED_MODEL, "response": "partial", "done": False}).encode()
        with self.assertRaises(Denied):
            model_proposal("test", http_open=lambda req, **kw: FakeResponse(body))

    def test_model_mismatch_denied(self):
        body = json.dumps({"model": "other:tag", "response": "partial", "done": True}).encode()
        with self.assertRaises(Denied):
            model_proposal("test", http_open=lambda req, **kw: FakeResponse(body))

    def test_redirect_attempt_is_not_retried(self):
        def blocked(req, **kwargs):
            raise URLError("redirect blocked")
        with self.assertRaises(Denied) as e:
            model_proposal("test", http_open=blocked)
        self.assertEqual(e.exception.code, "LOCAL_LLM_UNAVAILABLE")

    def test_huge_response_denied(self):
        with self.assertRaises(Denied) as e:
            model_proposal("test", http_open=lambda req, **kw: FakeResponse(b"a" * 20_000))
        self.assertEqual(e.exception.code, "LLM_RESPONSE_TOO_LARGE")

    def test_empty_answer_denied(self):
        body = json.dumps({"model": ALLOWED_MODEL, "response": "", "done": True}).encode()
        with self.assertRaises(Denied):
            model_proposal("test", http_open=lambda req, **kw: FakeResponse(body))


if __name__ == "__main__":
    unittest.main()
