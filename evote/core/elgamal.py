"""Exponential ElGamal encryption over the Edwards25519 prime-order group.

Key pair:      secret x,  public H = x*G
Encrypt m:     pick random r,   ciphertext = (A, B) = (r*G,  m*G + r*H)
Decrypt:       B - x*A = m*G,   then recover the small number m by search.

Why "exponential"? The message is put in the exponent (m*G), which makes the
scheme *additively homomorphic*:

    Enc(m1) + Enc(m2) = (r1*G + r2*G,  (m1+m2)*G + (r1+r2)*H) = Enc(m1 + m2)

So adding up every ballot's ciphertext gives an encryption of the vote
total, and only that total is ever decrypted. The price is that decryption
needs a small discrete-log search, which is fine because m <= number of voters.

ElGamal is also where the key exchange happens: r*G is an ephemeral
Diffie-Hellman public key and r*H = x*(r*G) is the shared secret that masks
the message.
"""

from dataclasses import dataclass

from evote.core import group
from evote.core.group import G, IDENTITY


@dataclass(frozen=True)
class Ciphertext:
    a: bytes  # r*G
    b: bytes  # m*G + r*H

    def __add__(self, other: "Ciphertext") -> "Ciphertext":
        return Ciphertext(group.add(self.a, other.a), group.add(self.b, other.b))

    def to_json(self) -> dict:
        return {"a": group.point_to_hex(self.a), "b": group.point_to_hex(self.b)}

    @classmethod
    def from_json(cls, data: dict) -> "Ciphertext":
        if not isinstance(data, dict):
            raise group.GroupError("ciphertext must be an object")
        return cls(group.point_from_hex(data.get("a")), group.point_from_hex(data.get("b")))


def keygen() -> tuple[int, bytes]:
    """Return (secret x, public H = x*G)."""
    x = group.random_scalar()
    return x, group.base_mul(x)


def encrypt(public_key: bytes, m: int, r: int | None = None) -> tuple[Ciphertext, int]:
    """Encrypt the small integer m. Returns the ciphertext and the randomness r.

    The caller needs r to build the zero-knowledge proofs and must then
    discard it: whoever knows r can prove what the ciphertext contains.
    """
    if r is None:
        r = group.random_scalar()
    a = group.base_mul(r)
    b = group.add(group.base_mul(m), group.smul(r, public_key))
    return Ciphertext(a, b), r


def aggregate(ciphertexts) -> Ciphertext:
    """Homomorphically add ciphertexts together."""
    total = Ciphertext(IDENTITY, IDENTITY)
    for ct in ciphertexts:
        total = total + ct
    return total


def decryption_share(secret_key: int, ct: Ciphertext) -> bytes:
    """D = x*A. Publishing D (with a proof) lets anyone compute m*G = B - D."""
    return group.smul(secret_key, ct.a)


def discrete_log_small(point: bytes, max_value: int) -> int:
    """Find m in [0, max_value] with m*G == point (linear search)."""
    candidate = IDENTITY
    for m in range(max_value + 1):
        if candidate == point:
            return m
        candidate = group.add(candidate, G)
    raise ValueError("plaintext is out of the expected range")


def decrypt_small(secret_key: int, ct: Ciphertext, max_value: int) -> int:
    return discrete_log_small(group.sub(ct.b, decryption_share(secret_key, ct)), max_value)
