"""Passphrase-protected key files.

Private keys never touch the disk in plaintext:

    key  = Argon2id(passphrase, random 16-byte salt)      # memory-hard KDF
    file = header || AES-256-GCM(key, random 12-byte nonce, secrets, aad=header)

Argon2id makes offline passphrase guessing expensive (each guess needs
``memory_cost`` KiB of RAM). AES-GCM gives confidentiality *and* integrity:
a wrong passphrase or any modified byte (including the KDF parameters in the
header, which are authenticated as associated data) fails with the same
error. Files are created with permissions 0600 (owner read/write only).
"""

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from evote.core.encoding import canonical_json

FORMAT = "evote-keystore-v1"

# OWASP-recommended style parameters: 64 MiB memory, 3 passes, 4 lanes.
DEFAULT_KDF = {"iterations": 3, "lanes": 4, "memory_cost": 64 * 1024}
# Minimum accepted when loading, so a tampered header cannot downgrade the KDF.
MIN_KDF = {"iterations": 1, "lanes": 1, "memory_cost": 8 * 1024}


class KeystoreError(Exception):
    pass


def _derive(passphrase: str, salt: bytes, params: dict) -> bytes:
    return Argon2id(salt=salt, length=32, **params).derive(passphrase.encode("utf-8"))


def write_private_file(path: str, data: bytes) -> None:
    """Create/overwrite a file readable only by its owner (chmod 600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)


def save(path: str, secrets_dict: dict, passphrase: str, label: str, kdf_params: dict | None = None) -> None:
    if len(passphrase) < 8:
        raise KeystoreError("passphrase must be at least 8 characters")
    params = dict(kdf_params or DEFAULT_KDF)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = {"format": FORMAT, "label": label, "kdf": {"name": "argon2id", "salt": salt.hex(), **params}}
    key = _derive(passphrase, salt, params)
    ciphertext = AESGCM(key).encrypt(nonce, canonical_json(secrets_dict), canonical_json(header))
    document = {"header": header, "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
    write_private_file(path, json.dumps(document, indent=2).encode("utf-8"))


def load(path: str, passphrase: str) -> dict:
    try:
        with open(path, "rb") as fh:
            document = json.loads(fh.read())
        header = document["header"]
        kdf = header["kdf"]
        if header.get("format") != FORMAT or kdf.get("name") != "argon2id":
            raise KeystoreError("unsupported key file format")
        params = {k: int(kdf[k]) for k in ("iterations", "lanes", "memory_cost")}
        if any(params[k] < MIN_KDF[k] for k in params):
            raise KeystoreError("key file KDF parameters are too weak")
        key = _derive(passphrase, bytes.fromhex(kdf["salt"]), params)
        plaintext = AESGCM(key).decrypt(
            bytes.fromhex(document["nonce"]), bytes.fromhex(document["ciphertext"]), canonical_json(header)
        )
    except InvalidTag as exc:
        raise KeystoreError("wrong passphrase, or the key file has been modified") from exc
    except (OSError, KeyError, ValueError, TypeError) as exc:
        raise KeystoreError(f"cannot read key file: {exc}") from exc
    return json.loads(plaintext)
