"""The prime-order group used by ElGamal and every zero-knowledge proof.

We work in the prime-order subgroup of the Edwards25519 elliptic curve (the
same curve used by Ed25519 signatures). All point arithmetic is performed by
**libsodium** through PyNaCl; this module only adds thin wrappers so the
protocol code reads like the maths and so that every point received from the
network is validated before use.

Notation (additive, as is usual for elliptic curves):
    G       the standard base point
    L       the order of the group (a 253-bit prime)
    k*P     scalar multiplication   ("P to the power k" in multiplicative notation)
    P + Q   point addition          ("P times Q" in multiplicative notation)
"""

import hashlib
import secrets

from nacl import bindings as _sodium

from evote import PROTOCOL

# Order of the prime-order subgroup of Edwards25519.
L = 2**252 + 27742317777372353535851937790883648493

# Encoding of the neutral element (the "point at infinity" / identity).
IDENTITY = b"\x01" + b"\x00" * 31


class GroupError(ValueError):
    """Raised when a point or scalar is malformed or outside the group."""


def _scalar_bytes(k: int) -> bytes:
    return (k % L).to_bytes(32, "little")


def random_scalar() -> int:
    """Uniform random non-zero scalar from the OS CSPRNG."""
    return secrets.randbelow(L - 1) + 1


def base_mul(k: int) -> bytes:
    """k*G."""
    k %= L
    if k == 0:
        return IDENTITY
    return _sodium.crypto_scalarmult_ed25519_base_noclamp(_scalar_bytes(k))


def smul(k: int, point: bytes) -> bytes:
    """k*P. libsodium itself refuses points that are not in the prime-order subgroup."""
    k %= L
    if k == 0 or point == IDENTITY:
        return IDENTITY
    try:
        return _sodium.crypto_scalarmult_ed25519_noclamp(_scalar_bytes(k), point)
    except Exception as exc:  # PyNaCl raises RuntimeError on invalid input
        raise GroupError("invalid point for scalar multiplication") from exc


def add(p: bytes, q: bytes) -> bytes:
    """P + Q."""
    if p == IDENTITY:
        return q
    if q == IDENTITY:
        return p
    return _sodium.crypto_core_ed25519_add(p, q)


def sub(p: bytes, q: bytes) -> bytes:
    """P - Q."""
    if q == IDENTITY:
        return p
    return _sodium.crypto_core_ed25519_sub(p, q)


def point_sum(points) -> bytes:
    total = IDENTITY
    for p in points:
        total = add(total, p)
    return total


G = base_mul(1)


# --------------------------------------------------------------------------
# Encoding / validation of data received from other parties
# --------------------------------------------------------------------------

def point_to_hex(p: bytes) -> str:
    return p.hex()


def point_from_hex(value: str) -> bytes:
    """Decode and *validate* a point.

    libsodium's ``is_valid_point`` checks that the encoding is canonical, that
    the point is on the curve, that it lies in the prime-order subgroup and
    that it is not of small order (this also rejects the identity). Skipping
    this check is a classic source of small-subgroup attacks.
    """
    if not isinstance(value, str) or len(value) != 64:
        raise GroupError("point must be 64 hex characters")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise GroupError("point is not valid hex") from exc
    if not _sodium.crypto_core_ed25519_is_valid_point(raw):
        raise GroupError("point is not a valid element of the prime-order group")
    return raw


def scalar_to_hex(k: int) -> str:
    return _scalar_bytes(k).hex()


def scalar_from_hex(value: str) -> int:
    """Decode a scalar and insist on the canonical (fully reduced) encoding."""
    if not isinstance(value, str) or len(value) != 64:
        raise GroupError("scalar must be 64 hex characters")
    try:
        k = int.from_bytes(bytes.fromhex(value), "little")
    except ValueError as exc:
        raise GroupError("scalar is not valid hex") from exc
    if k >= L:
        raise GroupError("scalar is not reduced modulo the group order")
    return k


# --------------------------------------------------------------------------
# Fiat-Shamir hashing
# --------------------------------------------------------------------------

def _absorb(h, item) -> None:
    """Unambiguous, type-tagged, length-prefixed encoding of transcript items."""
    if isinstance(item, bytes):
        h.update(b"B" + len(item).to_bytes(4, "big") + item)
    elif isinstance(item, str):
        data = item.encode("utf-8")
        h.update(b"S" + len(data).to_bytes(4, "big") + data)
    elif isinstance(item, int):
        data = str(item).encode("ascii")
        h.update(b"I" + len(data).to_bytes(4, "big") + data)
    elif isinstance(item, (list, tuple)):
        h.update(b"L" + len(item).to_bytes(4, "big"))
        for sub_item in item:
            _absorb(h, sub_item)
    else:
        raise TypeError(f"cannot hash item of type {type(item).__name__}")


def hash_to_scalar(label: str, *items) -> int:
    """Hash a full proof transcript to a challenge scalar.

    SHA-512 gives 512 bits which we reduce modulo L, so the result is
    statistically uniform. ``label`` separates the different proof types.
    """
    h = hashlib.sha512()
    _absorb(h, f"{PROTOCOL}/zkp/{label}")
    for item in items:
        _absorb(h, item)
    return int.from_bytes(h.digest(), "little") % L
