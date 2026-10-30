"""Docker command security constraints; integration also runs a real container in CI."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

from hanter_pilot.isolated_worker import IMAGE, isolated_sha256
from hanter_pilot.pilot import Denied


class IsolatedWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "synthetic.txt"
        self.path.write_bytes(b"synthetic evidence only")
        self.commands = []

    def fake_runner(self, cmd, **kwargs):
        self.commands.append((cmd, kwargs))
        body = self.path.read_bytes()
        output = json.dumps({"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})
        return CompletedProcess(cmd, 0, output, "")

    def rejected(self, code, **kwargs):
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(self.path, run=self.fake_runner, **kwargs)
        self.assertEqual(ctx.exception.code, code)

    def test_signed_offline_scope_and_second_sha256(self):
        result = isolated_sha256(self.path, run=self.fake_runner)
        self.assertEqual(result["qa"], "PASS_HOST_REHASH")
        self.assertFalse(result["production_authorized"])
        command, kwargs = self.commands[0]
        self.assertEqual(command[:3], ["docker", "run", "--rm"])
        for required in (
            "--pull=never", "--network=none", "--read-only",
            "--user=65534:65534", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=32",
            "--memory=128m", "--cpus=0.5",
        ):
            self.assertIn(required, command)
        self.assertEqual(command[command.index("--") + 1], IMAGE)
        self.assertEqual(kwargs["timeout"], 30)
        mounts = [x for x in command if x.startswith("type=bind,")]
        self.assertEqual(len(mounts), 1)
        self.assertIn("readonly", mounts[0])

    def test_unapproved_image_denied_before_launch(self):
        self.rejected("UNAPPROVED_IMAGE", image="untrusted:latest")
        self.assertEqual(self.commands, [])

    def test_symlink_denied(self):
        link = self.path.with_name("link")
        link.symlink_to(self.path)
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(link, run=self.fake_runner)
        self.assertEqual(ctx.exception.code, "UNSAFE_INPUT_PATH")

    def test_missing_file_denied(self):
        self.path.unlink()
        self.rejected("INPUT_MISSING")

    def test_oversized_file_denied(self):
        self.path.write_bytes(b"x" * 1_048_577)
        self.rejected("UNSAFE_INPUT_FILE")

    def test_failed_container_denied(self):
        def failed(cmd, **kwargs):
            return CompletedProcess(cmd, 125, "", "daemon unavailable")
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(self.path, run=failed)
        self.assertEqual(ctx.exception.code, "ISOLATED_RUNTIME_FAILED")

    def test_missing_docker_fails_closed(self):
        def failed(cmd, **kwargs):
            raise FileNotFoundError("docker")
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(self.path, run=failed)
        self.assertEqual(ctx.exception.code, "ISOLATED_RUNTIME_UNAVAILABLE")

    def test_timeout_fails_closed(self):
        def timeout(cmd, **kwargs):
            raise TimeoutExpired(cmd, 30)
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(self.path, run=timeout)
        self.assertEqual(ctx.exception.code, "ISOLATED_RUNTIME_UNAVAILABLE")

    def test_invalid_stdout_rejected(self):
        def fake(cmd, **kwargs):
            return CompletedProcess(cmd, 0, "not json", "")
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(self.path, run=fake)
        self.assertEqual(ctx.exception.code, "BAD_WORKER_OUTPUT")

    def test_mismatched_digest_denied(self):
        def fake(cmd, **kwargs):
            return CompletedProcess(cmd, 0, json.dumps({
                "sha256": "0" * 64, "bytes": len(self.path.read_bytes())
            }), "")
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(self.path, run=fake)
        self.assertEqual(ctx.exception.code, "HOST_QA_MISMATCH")

    def test_excessive_stdout_denied(self):
        def fake(cmd, **kwargs):
            return CompletedProcess(cmd, 0, "x" * 4096, "")
        with self.assertRaises(Denied) as ctx:
            isolated_sha256(self.path, run=fake)
        self.assertEqual(ctx.exception.code, "WORKER_OUTPUT_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()
