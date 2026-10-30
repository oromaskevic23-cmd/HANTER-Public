"""Encrypted *local* Ed25519 test-key vault, NOT an HSM or production KMS.

No passphrase is committed to Git or accepted over a network. The unencrypted
key exists briefly in process memory. Only intended for isolated development.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, load_pem_private_key,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VAULT_VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
MAX_FILE_BYTES = 16384
VAULT_FILENAME = "nca-private-keys.sealed.json"
ROLES = ("passport", "guardian", "approval", "revocation")


class VaultError(ValueError):
    """A non-secret error code, safe for reporting to the local developer."""


def _require_owner_only(path: Path, *, directory: bool) -> None:
    if path.is_symlink():
        raise VaultError("SYMLINK_PATH")
    st = path.stat()
    if st.st_uid != os.getuid():
        raise VaultError("NOT_OWNER")
    expected = stat.S_IFDIR if directory else stat.S_IFREG
    if stat.S_IFMT(st.st_mode) != expected:
        raise VaultError("WRONG_FILE_TYPE")
    if (st.st_mode & 0o077) != 0:
        raise VaultError("INSECURE_PERMISSIONS")


def _derive(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase)


def _check_passphrase(passphrase: bytes) -> None:
    if type(passphrase) is not bytes or len(passphrase) < 16:
        raise VaultError("WEAK_PASSPHRASE")


def _serialize(keys: dict[str, Ed25519PrivateKey]) -> bytes:
    if set(keys) != set(ROLES) or any(
        not isinstance(key, Ed25519PrivateKey) for key in keys.values()
    ):
        raise VaultError("INVALID_ROLE_KEYS")
    payload = {
        role: base64.b64encode(key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )).decode("ascii") for role, key in keys.items()
    }
    return json.dumps(payload, sort_keys=True).encode("ascii")


def create_local_vault(directory: Path, passphrase: bytes,
                       keys: dict[str, Ed25519PrivateKey]) -> Path:
    """Create an owner-only sealed file. Never overwrite an existing vault."""
    _check_passphrase(passphrase)
    if directory.exists():
        _require_owner_only(directory, directory=True)
    else:
        directory.mkdir(mode=0o700, parents=False)
        _require_owner_only(directory, directory=True)
    vault_path = directory / VAULT_FILENAME
    if vault_path.exists() or vault_path.is_symlink():
        raise VaultError("VAULT_ALREADY_EXISTS")
    cleartext = _serialize(keys)
    salt, nonce = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(NONCE_SIZE)
    envelope = {
        "version": VAULT_VERSION,
        "kdf": "scrypt-n32768-r8-p1",
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }
    aad = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(nonce, cleartext, aad)
    record = {**envelope, "ciphertext": base64.b64encode(ciphertext).decode()}
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    # Exclusive create prevents accidental secret overwrite; no plaintext on disk.
    fd = os.open(vault_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(encoded)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        vault_path.unlink(missing_ok=True)
        raise
    return vault_path


def open_local_vault(directory: Path, passphrase: bytes) -> dict[str, Ed25519PrivateKey]:
    """Return private key objects in memory; never echo secret material."""
    _check_passphrase(passphrase)
    _require_owner_only(directory, directory=True)
    vault = directory / VAULT_FILENAME
    _require_owner_only(vault, directory=False)
    if vault.stat().st_size > MAX_FILE_BYTES:
        raise VaultError("VAULT_TOO_LARGE")
    data = vault.read_bytes()
    try:
        record = json.loads(data)
        if set(record) != {"version", "kdf", "cipher", "salt", "nonce", "ciphertext"}:
            raise VaultError("MALFORMED_VAULT")
        if (record["version"] != VAULT_VERSION
                or record["kdf"] != "scrypt-n32768-r8-p1"
                or record["cipher"] != "aes-256-gcm"):
            raise VaultError("UNSUPPORTED_VAULT")
        salt = base64.b64decode(record["salt"], validate=True)
        nonce = base64.b64decode(record["nonce"], validate=True)
        ciphertext = base64.b64decode(record["ciphertext"], validate=True)
        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
            raise VaultError("MALFORMED_VAULT")
        aad_fields = {k: record[k] for k in ("version", "kdf", "cipher", "salt", "nonce")}
        aad = json.dumps(aad_fields, sort_keys=True, separators=(",", ":")).encode()
        clear = AESGCM(_derive(passphrase, salt)).decrypt(nonce, ciphertext, aad)
        serialized = json.loads(clear)
        if set(serialized) != set(ROLES):
            raise VaultError("INVALID_ROLE_KEYS")
        results = {}
        for role in ROLES:
            private = load_pem_private_key(base64.b64decode(serialized[role], validate=True), password=None)
            if not isinstance(private, Ed25519PrivateKey):
                raise VaultError("INVALID_ROLE_KEYS")
            results[role] = private
        return results
    except (InvalidTag, UnicodeError, KeyError, ValueError, TypeError) as exc:
        raise VaultError("VAULT_AUTHENTICATION_FAILED") from None


def disposable_vault_demo() -> dict[str, object]:
    """Smoke-test only: keys are synthetic and directory self-destructs."""
    with tempfile.TemporaryDirectory(prefix="hanter-vault-demo-") as root:
        folder = Path(root) / "secrets"
        passphrase = secrets.token_bytes(32)
        keys = {role: Ed25519PrivateKey.generate() for role in ROLES}
        vault = create_local_vault(folder, passphrase, keys)
        restored = open_local_vault(folder, passphrase)
        test_message = b"IMPERIAL Core offline NCA trial"
        for role in ROLES:
            restored[role].public_key().verify(restored[role].sign(test_message), test_message)
        return {
            "roles": len(restored),
            "stored_as_ciphertext": b"BEGIN PRIVATE KEY" not in vault.read_bytes(),
            "owner_only_file_permissions": oct(vault.stat().st_mode & 0o777),
            "operational_secret_manager": False,
        }


if __name__ == "__main__":
    print(json.dumps(disposable_vault_demo(), indent=2))
