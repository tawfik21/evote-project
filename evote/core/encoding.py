"""Canonical encodings and small hashing helpers.

Everything that gets signed or hashed is first turned into *canonical* JSON
(sorted keys, no whitespace). Without a canonical form, two parties could
serialise the same object differently and signatures/hashes would not match.
"""

import hashlib
import json
from typing import Any

from evote import PROTOCOL


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def domain_bytes(domain: str) -> bytes:
    """Domain-separation prefix, e.g. b"evote/v1/receipt\\x00".

    Every signature and hash in the system is computed over a different
    prefix, so a value produced for one purpose (say, a receipt) can never be
    replayed as if it were another (say, a ballot).
    """
    return f"{PROTOCOL}/{domain}".encode("ascii") + b"\x00"


def sha256_hex(domain: str, obj: Any) -> str:
    """SHA-256 over a domain prefix plus the canonical JSON of ``obj``."""
    return hashlib.sha256(domain_bytes(domain) + canonical_json(obj)).hexdigest()
