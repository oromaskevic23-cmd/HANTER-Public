"""CI triggers and branch readiness guardrails, without external dependencies."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CIReleasePolicyTest(unittest.TestCase):
    def test_engineering_suite_runs_on_main_and_pull_requests(self):
        workflow = (ROOT / ".github/workflows/hanter-offline-pilot.yml").read_text()
        self.assertIn("  push:\n    branches: [main]\n  pull_request:\n", workflow)
        self.assertIn("python3 -m unittest discover -s tests -p 'test_*.py' -v", workflow)
        self.assertIn("python3 -m hanter_pilot.isolated_worker", workflow)
        self.assertIn("python3 -m hanter_pilot.signed_demo", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)

    def test_real_llm_remains_manual_only(self):
        workflow = (ROOT / ".github/workflows/hanter-one-time-local-llm.yml").read_text()
        self.assertIn("on:\n  workflow_dispatch:", workflow)
        for auto_trigger in ("  push:", "  pull_request:", "  schedule:"):
            self.assertNotIn(auto_trigger, workflow)

    def test_separate_owner_review_scope_is_documented(self):
        owners = (ROOT / ".github/CODEOWNERS").read_text()
        self.assertIn("/hanter_pilot/ @oromaskevic23-cmd", owners)
        self.assertIn("/tests/ @oromaskevic23-cmd", owners)
        self.assertIn("/.github/workflows/hanter-offline-pilot.yml @oromaskevic23-cmd", owners)


if __name__ == "__main__":
    unittest.main()
