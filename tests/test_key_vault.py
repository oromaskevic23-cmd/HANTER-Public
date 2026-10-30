"""Reproducible security regressions for the local sealed development vault."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hanter_pilot.key_vault import (
    ROLES, VaultError, create_local_vault, disposable_vault_demo,
    open_local_vault,
)


class SealedKeyVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / "vault"
        self.passphrase = b"test-in-memory-32-byte-secret-password"
        self.keys = {role: Ed25519PrivateKey.generate() for role in ROLES}

    def make(self):
        return create_local_vault(self.folder, self.passphrase, self.keys)

    def test_encrypts_and_recovers_four_separate_role_keys(self):
        f = self.make()
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.folder.stat().st_mode), 0o700)
        self.assertNotIn(b"PRIVATE KEY", f.read_bytes())
        imported = open_local_vault(self.folder, self.passphrase)
        for role in ROLES:
            payload = b"local-test-only"
            original_sig = self.keys[role].sign(payload)
            imported[role].public_key().verify(original_sig, payload)
            imported[role].public_key().verify(imported[role].sign(payload), payload)

    def test_wrong_password_rejected(self):
        self.make()
        with self.assertRaises(VaultError):
            open_local_vault(self.folder, b"wrong-password-for-test-only-0001")

    def test_authentication_detects_ciphertext_tampering(self):
        f = self.make()
        doc = json.loads(f.read_text())
        c = doc["ciphertext"]
        doc["ciphertext"] = ("A" if c[0] != "A" else "B") + c[1:]
        f.write_text(json.dumps(doc))
        with self.assertRaises(VaultError):
            open_local_vault(self.folder, self.passphrase)

    def test_aad_detects_nonce_tampering(self):
        f = self.make()
        doc = json.loads(f.read_text())
        n = doc["nonce"]
        doc["nonce"] = ("A" if n[0] != "A" else "B") + n[1:]
        f.write_text(json.dumps(doc))
        with self.assertRaises(VaultError):
            open_local_vault(self.folder, self.passphrase)

    def test_refuses_private_key_overwrite(self):
        self.make()
        with self.assertRaises(VaultError) as e:
            self.make()
        self.assertEqual(str(e.exception), "VAULT_ALREADY_EXISTS")

    def test_rejects_weak_passphrase(self):
        with self.assertRaises(VaultError):
            create_local_vault(self.folder, b"weak", self.keys)

    def test_rejects_insecure_vault_file_perms(self):
        f = self.make()
        os.chmod(f, 0o644)
        with self.assertRaises(VaultError) as e:
            open_local_vault(self.folder, self.passphrase)
        self.assertEqual(str(e.exception), "INSECURE_PERMISSIONS")

    def test_rejects_insecure_directory_perms(self):
        self.make()
        os.chmod(self.folder, 0o755)
        with self.assertRaises(VaultError):
            open_local_vault(self.folder, self.passphrase)

    def test_rejects_symlinked_vault_directory(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        self.folder.symlink_to(real, target_is_directory=True)
        with self.assertRaises(VaultError):
            create_local_vault(self.folder, self.passphrase, self.keys)

    def test_test_only_disposable_vault(self):
        v = disposable_vault_demo()
        self.assertEqual(v["roles"], 4)
        self.assertEqual(v["owner_only_file_permissions"], "0o600")
        self.assertTrue(v["stored_as_ciphertext"])
        self.assertFalse(v["operational_secret_manager"])


if __name__ == "__main__":
    unittest.main()
