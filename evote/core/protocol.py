"""Election protocol messages: how each one is built and how it is verified.

The server, the authority, the voters and the auditor all call the *same*
verification functions in this file, so there is exactly one definition of
"a valid ballot", "a valid result", and so on.

Message                  signed by     contains
-----------------------  ------------  ------------------------------------------------
election manifest        authority     candidates, ElGamal public key + Schnorr proof
enrolment-code list      authority     SHA-256 hashes of one-time enrolment codes
voter enrolment          voter         voter's public keys + Schnorr proof for login key
ballot                   voter         one ElGamal ciphertext per candidate,
                                       an OR-proof per ciphertext (it encrypts 0 or 1),
                                       a DLEQ proof that they sum to exactly 1
receipt                  server        position + hash of the ballot on the board
close                    authority     the board head hash it is closing over
result                   authority     vote counts + a DLEQ proof per candidate that
                                       the aggregate was decrypted correctly
"""

import secrets
import time

from evote.core import elgamal, group, signing, zkp
from evote.core.board import compute_hash
from evote.core.elgamal import Ciphertext
from evote.core.encoding import sha256_hex
from evote.core.group import G, base_mul, sub

MAX_CANDIDATES = 20
GROUP_NAME = "edwards25519 prime-order subgroup (libsodium)"


class ValidationError(ValueError):
    """A protocol message failed verification. The message is safe to show."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValidationError(reason)


def _body(envelope) -> dict:
    _require(isinstance(envelope, dict) and isinstance(envelope.get("body"), dict), "malformed signed message")
    return envelope["body"]


def _str_field(body: dict, name: str, max_len: int = 128) -> str:
    value = body.get(name)
    _require(isinstance(value, str) and 0 < len(value) <= max_len, f"field '{name}' missing or invalid")
    return value


def _point(value, what: str) -> bytes:
    try:
        return group.point_from_hex(value)
    except group.GroupError as exc:
        raise ValidationError(f"{what}: {exc}") from exc


def _ciphertext(value, what: str) -> Ciphertext:
    try:
        return Ciphertext.from_json(value)
    except group.GroupError as exc:
        raise ValidationError(f"{what}: {exc}") from exc


def _check_proof(ok_fn, what: str) -> None:
    try:
        ok = ok_fn()
    except (zkp.ProofError, group.GroupError) as exc:
        raise ValidationError(f"{what} is malformed: {exc}") from exc
    _require(ok, f"{what} does not verify")


def now() -> int:
    return int(time.time())


# ==========================================================================
# Election manifest (authority)
# ==========================================================================

def create_manifest(title: str, candidates: list[str], elgamal_secret: int, elgamal_public: bytes,
                    authority_key) -> dict:
    _require(2 <= len(candidates) <= MAX_CANDIDATES, "need between 2 and 20 candidates")
    _require(len(set(candidates)) == len(candidates), "candidate names must be unique")
    election_id = secrets.token_hex(16)
    body = {
        "election_id": election_id,
        "title": title,
        "candidates": candidates,
        "group": GROUP_NAME,
        "elgamal_public_key": group.point_to_hex(elgamal_public),
        # Proves the authority really knows the secret key for this public key.
        "election_key_proof": zkp.schnorr_nizk_prove(elgamal_secret, elgamal_public, "election-key", [election_id]),
        "authority_public_key": signing.public_hex(authority_key),
        "created_at": now(),
    }
    return signing.signed(authority_key, "manifest", body)


def verify_manifest(envelope, authority_public_key: str | None = None) -> dict:
    """Return the manifest body if valid. Pin the authority key when known."""
    body = _body(envelope)
    election_id = _str_field(body, "election_id", 64)
    signer = _str_field(body, "authority_public_key", 64)
    if authority_public_key is not None:
        _require(signer == authority_public_key, "manifest is not from the expected authority")
    _require(signing.verify_signed(signer, "manifest", envelope), "manifest signature is invalid")
    candidates = body.get("candidates")
    _require(isinstance(candidates, list) and 2 <= len(candidates) <= MAX_CANDIDATES
             and all(isinstance(c, str) for c in candidates), "invalid candidate list")
    public = _point(body.get("elgamal_public_key"), "election public key")
    _check_proof(lambda: zkp.schnorr_nizk_verify(public, body.get("election_key_proof"), "election-key",
                                                  [election_id]), "election key proof")
    return body


def election_public_key(manifest: dict) -> bytes:
    return group.point_from_hex(manifest["elgamal_public_key"])


# ==========================================================================
# Enrolment codes (authority -> server) and voter enrolment (voter -> server)
# ==========================================================================

def new_enrolment_code() -> str:
    """80 random bits, shown as XXXX-XXXX-XXXX-XXXX (base32, no 0/1/O/I)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(16))
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def enrolment_code_hash(election_id: str, voter_id: str, code: str) -> str:
    # Codes carry 80 bits of entropy, so a fast hash is enough: guessing is infeasible.
    return sha256_hex("enrolment-code", {"election_id": election_id, "voter_id": voter_id,
                                         "code": code.strip().upper()})


def create_enrolment_request(election_id: str, voter_id: str, sign_key, login_secret: int) -> dict:
    login_public = base_mul(login_secret)
    body = {
        "election_id": election_id,
        "voter_id": voter_id,
        "sign_public_key": signing.public_hex(sign_key),
        "login_public_key": group.point_to_hex(login_public),
        # Proof of possession: stops anyone registering a key they do not own.
        "login_key_proof": zkp.schnorr_nizk_prove(login_secret, login_public, "login-key",
                                                  [election_id, voter_id]),
    }
    return signing.signed(sign_key, "enrol", body)


def verify_enrolment(envelope, election_id: str) -> dict:
    body = _body(envelope)
    voter_id = _str_field(body, "voter_id", 64)
    _require(body.get("election_id") == election_id, "enrolment is for a different election")
    sign_public = _str_field(body, "sign_public_key", 64)
    _require(signing.verify_signed(sign_public, "enrol", envelope), "enrolment signature is invalid")
    login_public = _point(body.get("login_public_key"), "login public key")
    _check_proof(lambda: zkp.schnorr_nizk_verify(login_public, body.get("login_key_proof"), "login-key",
                                                  [election_id, voter_id]), "login key proof")
    return body


# ==========================================================================
# Ballots (voter)
# ==========================================================================

def _encrypts_value(ct: Ciphertext, public: bytes, value: int) -> zkp.Statement:
    """DLEQ statement "(A, B) encrypts `value`":  A = r*G  and  B - value*G = r*H."""
    return (G, ct.a, public, sub(ct.b, base_mul(value)))


def create_ballot(manifest: dict, voter_id: str, choice_index: int, sign_key) -> dict:
    """Encrypt a one-hot vote vector and attach the zero-knowledge proofs."""
    n = len(manifest["candidates"])
    _require(0 <= choice_index < n, "choice out of range")
    election_id = manifest["election_id"]
    public = election_public_key(manifest)

    ciphertexts, entry_proofs, randomness = [], [], []
    for i in range(n):
        vote = 1 if i == choice_index else 0
        ct, r = elgamal.encrypt(public, vote)
        statements = [_encrypts_value(ct, public, 0), _encrypts_value(ct, public, 1)]
        entry_proofs.append(zkp.or_prove(statements, vote, r, "ballot-entry", [election_id, voter_id, i]))
        ciphertexts.append(ct)
        randomness.append(r)

    total = elgamal.aggregate(ciphertexts)
    total_r = sum(randomness) % group.L
    sum_proof = zkp.dleq_prove(_encrypts_value(total, public, 1), total_r, "ballot-sum", [election_id, voter_id])
    # The randomness r would let the voter prove their vote to a coercer; drop it.
    randomness.clear()

    body = {
        "election_id": election_id,
        "voter_id": voter_id,
        "ciphertexts": [ct.to_json() for ct in ciphertexts],
        "entry_proofs": entry_proofs,
        "sum_proof": sum_proof,
    }
    return signing.signed(sign_key, "ballot", body)


def verify_ballot(manifest: dict, voter_sign_public_key: str, envelope) -> list[Ciphertext]:
    """Check signature and every proof. Returns the decoded ciphertexts."""
    body = _body(envelope)
    election_id = manifest["election_id"]
    voter_id = _str_field(body, "voter_id", 64)
    _require(body.get("election_id") == election_id, "ballot is for a different election")
    _require(signing.verify_signed(voter_sign_public_key, "ballot", envelope), "ballot signature is invalid")

    n = len(manifest["candidates"])
    raw_cts, proofs = body.get("ciphertexts"), body.get("entry_proofs")
    _require(isinstance(raw_cts, list) and len(raw_cts) == n, "wrong number of ciphertexts")
    _require(isinstance(proofs, list) and len(proofs) == n, "wrong number of entry proofs")
    public = election_public_key(manifest)

    cts = [_ciphertext(raw, f"ciphertext {i}") for i, raw in enumerate(raw_cts)]
    for i, (ct, proof) in enumerate(zip(cts, proofs)):
        statements = [_encrypts_value(ct, public, 0), _encrypts_value(ct, public, 1)]
        _check_proof(lambda: zkp.or_verify(statements, proof, "ballot-entry", [election_id, voter_id, i]),
                     f"0-or-1 proof for candidate {i}")
    total = elgamal.aggregate(cts)
    _check_proof(lambda: zkp.dleq_verify(_encrypts_value(total, public, 1), body.get("sum_proof"),
                                         "ballot-sum", [election_id, voter_id]), "exactly-one-vote proof")
    return cts


def ballot_tracker(envelope) -> str:
    """Public tracking code for a ballot (a hash of the signed ballot)."""
    return sha256_hex("tracker", envelope)


# ==========================================================================
# Receipts and board head (server)
# ==========================================================================

def create_receipt(server_key, election_id: str, voter_id: str, entry: dict, tracker: str) -> dict:
    body = {"election_id": election_id, "voter_id": voter_id, "index": entry["index"],
            "entry_hash": entry["hash"], "tracker": tracker, "timestamp": entry["timestamp"]}
    return signing.signed(server_key, "receipt", body)


def create_head(server_key, election_id: str, length: int, head: str) -> dict:
    return signing.signed(server_key, "board-head",
                          {"election_id": election_id, "length": length, "head_hash": head, "timestamp": now()})


# ==========================================================================
# Closing the election and publishing the result (authority)
# ==========================================================================

def create_close(authority_key, election_id: str, head: str, ballot_count: int) -> dict:
    body = {"election_id": election_id, "action": "close", "head_hash": head,
            "ballot_count": ballot_count, "timestamp": now()}
    return signing.signed(authority_key, "close", body)


def verify_close(envelope, manifest: dict) -> dict:
    body = _body(envelope)
    _require(body.get("election_id") == manifest["election_id"], "close is for a different election")
    _require(body.get("action") == "close", "not a close request")
    _require(signing.verify_signed(manifest["authority_public_key"], "close", envelope),
             "close request is not signed by the election authority")
    _str_field(body, "head_hash", 64)
    return body


def compute_result(manifest: dict, elgamal_secret: int, ballot_cts: list[list[Ciphertext]],
                   close_entry_hash: str, authority_key) -> dict:
    """Aggregate all ballots, decrypt only the totals, and prove each decryption."""
    election_id = manifest["election_id"]
    public = election_public_key(manifest)
    n = len(manifest["candidates"])
    aggregates = [elgamal.aggregate(b[i] for b in ballot_cts) for i in range(n)]

    shares, proofs, counts = [], [], []
    for i, agg in enumerate(aggregates):
        share = elgamal.decryption_share(elgamal_secret, agg)          # D = x*A
        # Proves log_G(H) == log_A(D), i.e. D was computed with the real secret key.
        proofs.append(zkp.dleq_prove((G, public, agg.a, share), elgamal_secret, "decryption", [election_id, i]))
        shares.append(group.point_to_hex(share))
        counts.append(elgamal.discrete_log_small(sub(agg.b, share), len(ballot_cts)))

    body = {
        "election_id": election_id,
        "close_hash": close_entry_hash,
        "candidates": manifest["candidates"],
        "aggregate": [ct.to_json() for ct in aggregates],
        "decryption_shares": shares,
        "decryption_proofs": proofs,
        "counts": counts,
        "total_ballots": len(ballot_cts),
    }
    return signing.signed(authority_key, "result", body)


def _point_or_identity(value, what: str) -> bytes:
    if value == group.point_to_hex(group.IDENTITY):
        return group.IDENTITY
    return _point(value, what)


def verify_result(envelope, manifest: dict, ballot_cts: list[list[Ciphertext]], close_entry_hash: str) -> dict:
    """Recompute the aggregate from the board and check every decryption proof."""
    body = _body(envelope)
    election_id = manifest["election_id"]
    n = len(manifest["candidates"])
    _require(body.get("election_id") == election_id, "result is for a different election")
    _require(signing.verify_signed(manifest["authority_public_key"], "result", envelope),
             "result is not signed by the election authority")
    _require(body.get("close_hash") == close_entry_hash, "result does not refer to the close entry")
    _require(body.get("candidates") == manifest["candidates"], "candidate list does not match manifest")
    _require(body.get("total_ballots") == len(ballot_cts), "ballot count does not match the board")

    counts = body.get("counts")
    _require(isinstance(counts, list) and len(counts) == n
             and all(isinstance(c, int) and 0 <= c <= len(ballot_cts) for c in counts), "invalid counts")
    _require(sum(counts) == len(ballot_cts), "counts do not add up to the number of ballots")

    public = election_public_key(manifest)
    expected = [elgamal.aggregate(b[i] for b in ballot_cts) for i in range(n)]
    _require(body.get("aggregate") == [ct.to_json() for ct in expected],
             "aggregate ciphertexts do not match the ballots on the board")
    shares, proofs = body.get("decryption_shares"), body.get("decryption_proofs")
    _require(isinstance(shares, list) and len(shares) == n and isinstance(proofs, list) and len(proofs) == n,
             "missing decryption proofs")

    for i, agg in enumerate(expected):
        share = _point_or_identity(shares[i], f"decryption share {i}")
        _check_proof(lambda: zkp.dleq_verify((G, public, agg.a, share), proofs[i], "decryption",
                                             [election_id, i]), f"decryption proof for candidate {i}")
        _require(sub(agg.b, share) == base_mul(counts[i]),
                 f"announced count for '{manifest['candidates'][i]}' is not the decrypted value")
    return body


def entry_hash_of(entry: dict) -> str:
    return compute_hash(entry)
