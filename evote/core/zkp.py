"""Zero-knowledge proofs.

Every proof here is a Sigma protocol (commit -> challenge -> response):

1. Schnorr proof of knowledge of a discrete log:  "I know x with X = x*G".
     - interactive version  -> used for voter LOGIN (the server picks the challenge)
     - non-interactive (Fiat-Shamir) -> used by the authority to prove it owns
       the election key, and by voters to prove they own their login key at
       enrolment.

2. Chaum-Pedersen proof of equal discrete logs (DLEQ):
       "I know w with Q1 = w*P1 AND Q2 = w*P2"
     -> used for the "ballot sums to exactly one vote" proof and for the
        authority's "I decrypted the tally correctly" proof.

3. Disjunctive (OR) Chaum-Pedersen proof (Cramer-Damgaard-Schoenmakers 1994):
       "statement 0 is true OR statement 1 is true", without revealing which.
     -> used to prove every ballot entry encrypts 0 or 1.

Non-interactive proofs use the *strong* Fiat-Shamir transform: the challenge
hashes the context (election id, voter id, ...), the generators, the
statement and the commitments. Leaving any of these out ("weak" Fiat-Shamir)
broke real voting systems, including Helios (Bernhard, Pereira, Warinschi 2012).

Proofs are stored compactly as lists of challenges c_i and responses z_i; the
verifier recomputes the commitments as  T = z*P - c*Q  and checks that the
challenges hash correctly.
"""

from evote.core import group
from evote.core.group import G, L, base_mul, hash_to_scalar, random_scalar, smul, sub


class ProofError(ValueError):
    """A proof is malformed. (A well-formed but false proof just verifies False.)"""


# A DLEQ statement (P1, Q1, P2, Q2) claims: exists w with Q1 = w*P1 and Q2 = w*P2.
Statement = tuple[bytes, bytes, bytes, bytes]


def _decode_scalars(values, expected_len: int) -> list[int]:
    if not isinstance(values, list) or len(values) != expected_len:
        raise ProofError("proof has the wrong number of components")
    try:
        return [group.scalar_from_hex(v) for v in values]
    except group.GroupError as exc:
        raise ProofError(str(exc)) from exc


# --------------------------------------------------------------------------
# Disjunctive Chaum-Pedersen (OR) proof. A single DLEQ is the 1-branch case.
# --------------------------------------------------------------------------

def or_prove(statements: list[Statement], real_index: int, witness: int, label: str, context) -> dict:
    """Prove that statements[real_index] holds, hiding which one it is.

    For the true branch we run the honest protocol. For every false branch
    we *simulate* a transcript: pick the challenge and response first, then
    solve for the commitment. The verifier fixes the overall challenge c
    through the hash, so the prover can only choose all-but-one of the c_i;
    the remaining one is forced, which is why at least one branch must be real.
    """
    n = len(statements)
    challenges = [0] * n
    responses = [0] * n
    commitments = [None] * n
    nonce = random_scalar()

    for i, (p1, q1, p2, q2) in enumerate(statements):
        if i == real_index:
            commitments[i] = (smul(nonce, p1), smul(nonce, p2))
        else:
            challenges[i] = random_scalar()
            responses[i] = random_scalar()
            commitments[i] = (
                sub(smul(responses[i], p1), smul(challenges[i], q1)),
                sub(smul(responses[i], p2), smul(challenges[i], q2)),
            )

    total = hash_to_scalar(label, context, [list(s) for s in statements], [list(t) for t in commitments])
    challenges[real_index] = (total - sum(c for i, c in enumerate(challenges) if i != real_index)) % L
    responses[real_index] = (nonce + challenges[real_index] * witness) % L
    return {
        "c": [group.scalar_to_hex(c) for c in challenges],
        "z": [group.scalar_to_hex(z) for z in responses],
    }


def or_verify(statements: list[Statement], proof: dict, label: str, context) -> bool:
    if not isinstance(proof, dict):
        raise ProofError("proof must be an object")
    challenges = _decode_scalars(proof.get("c"), len(statements))
    responses = _decode_scalars(proof.get("z"), len(statements))
    commitments = []
    for (p1, q1, p2, q2), c, z in zip(statements, challenges, responses):
        commitments.append((sub(smul(z, p1), smul(c, q1)), sub(smul(z, p2), smul(c, q2))))
    expected = hash_to_scalar(label, context, [list(s) for s in statements], [list(t) for t in commitments])
    return sum(challenges) % L == expected


def dleq_prove(statement: Statement, witness: int, label: str, context) -> dict:
    return or_prove([statement], 0, witness, label, context)


def dleq_verify(statement: Statement, proof: dict, label: str, context) -> bool:
    return or_verify([statement], proof, label, context)


# --------------------------------------------------------------------------
# Schnorr proof of knowledge of x with X = x*G (non-interactive)
# --------------------------------------------------------------------------

def schnorr_nizk_prove(secret: int, public: bytes, label: str, context) -> dict:
    nonce = random_scalar()
    commitment = base_mul(nonce)
    c = hash_to_scalar(label, context, G, public, commitment)
    z = (nonce + c * secret) % L
    return {"c": group.scalar_to_hex(c), "z": group.scalar_to_hex(z)}


def schnorr_nizk_verify(public: bytes, proof: dict, label: str, context) -> bool:
    if not isinstance(proof, dict):
        raise ProofError("proof must be an object")
    c, z = _decode_scalars([proof.get("c"), proof.get("z")], 2)
    commitment = sub(base_mul(z), smul(c, public))
    return c == hash_to_scalar(label, context, G, public, commitment)


# --------------------------------------------------------------------------
# Schnorr identification protocol (interactive) - used for voter login
# --------------------------------------------------------------------------

class SchnorrProver:
    """Client side of the interactive Schnorr login.

        client                                server
        k random, T = k*G      --- T --->
                               <--- c ---     c random, single use
        z = k + c*s            --- z --->     accept iff z*G == T + c*Y

    The nonce k is used for exactly one challenge and then destroyed: if the
    same k ever answered two different challenges, anyone could solve
    s = (z1 - z2) / (c1 - c2) and steal the voter's login key.
    """

    def __init__(self, secret: int):
        self._secret = secret
        self._nonce = random_scalar()
        self.commitment = base_mul(self._nonce)

    def respond(self, challenge: int) -> int:
        if self._nonce is None:
            raise RuntimeError("a Schnorr nonce must never answer two challenges")
        z = (self._nonce + challenge * self._secret) % L
        self._nonce = None
        return z


def new_login_challenge() -> int:
    return random_scalar()


def schnorr_login_verify(public: bytes, commitment: bytes, challenge: int, response: int) -> bool:
    return base_mul(response) == group.add(commitment, smul(challenge, public))
