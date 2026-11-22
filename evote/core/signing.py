"""Ed25519 digital signatures (pyca/cryptography, OpenSSL backend).

Signatures give *non-repudiation*: a voter cannot later deny casting a ballot
they signed, and the server cannot deny issuing a receipt it signed.

Every signature is over  domain-prefix || canonical-JSON(body), so a
signature made for one purpose can never be reused for another.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from evote.core.encoding import canonical_json, domain_bytes


def generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_to_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()


def private_from_hex(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(key: Ed25519PrivateKey, domain: str, body) -> str:
    return key.sign(domain_bytes(domain) + canonical_json(body)).hex()


def verify(public_key_hex: str, domain: str, body, signature_hex: str) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), domain_bytes(domain) + canonical_json(body))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def signed(key: Ed25519PrivateKey, domain: str, body: dict) -> dict:
    """Wrap a body with its signature: {"body": ..., "signature": ...}."""
    return {"body": body, "signature": sign(key, domain, body)}


def verify_signed(public_key_hex: str, domain: str, envelope) -> bool:
    if not isinstance(envelope, dict) or "body" not in envelope or "signature" not in envelope:
        return False
    if not isinstance(envelope["signature"], str):
        return False
    return verify(public_key_hex, domain, envelope["body"], envelope["signature"])
