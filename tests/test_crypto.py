"""Unit tests for the cryptographic building blocks."""

import json
import os
import random
import stat

import pytest

from evote.core import board, elgamal, group, keystore, signing, zkp
from evote.core.group import G, L, IDENTITY, base_mul, sub

from conftest import FAST_KDF, PASS


# ----------------------------------------------------------------- group
def test_group_basics():
    a, b = group.random_scalar(), group.random_scalar()
    assert group.add(base_mul(a), base_mul(b)) == base_mul(a + b)
    assert group.smul(L, G) == IDENTITY
    assert sub(base_mul(a), base_mul(a)) == IDENTITY


def test_point_validation_rejects_bad_points():
    with pytest.raises(group.GroupError):
        group.point_from_hex(IDENTITY.hex())                         # identity
    small_order = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    with pytest.raises(group.GroupError):
        group.point_from_hex(small_order)                            # point of order 2
    with pytest.raises(group.GroupError):
        group.point_from_hex("zz" * 32)
    with pytest.raises(group.GroupError):
        group.scalar_from_hex((L + 1).to_bytes(32, "little").hex())  # non-canonical scalar


# --------------------------------------------------------------- elgamal
def test_elgamal_round_trip_and_homomorphism():
    x, h = elgamal.keygen()
    votes = [random.randint(0, 1) for _ in range(30)]
    cts = [elgamal.encrypt(h, v)[0] for v in votes]
    assert elgamal.decrypt_small(x, cts[0], 1) == votes[0]
    assert elgamal.decrypt_small(x, elgamal.aggregate(cts), 30) == sum(votes)


def test_elgamal_is_randomised():
    _, h = elgamal.keygen()
    assert elgamal.encrypt(h, 1)[0] != elgamal.encrypt(h, 1)[0]


def test_wrong_key_does_not_decrypt():
    x, h = elgamal.keygen()
    other, _ = elgamal.keygen()
    ct, _ = elgamal.encrypt(h, 1)
    with pytest.raises(ValueError):
        elgamal.decrypt_small(other, ct, 50)


# ------------------------------------------------------------------- zkp
def _stmts(ct, h):
    return [(G, ct.a, h, sub(ct.b, base_mul(v))) for v in (0, 1)]


@pytest.mark.parametrize("vote", [0, 1])
def test_or_proof_completeness(vote):
    _, h = elgamal.keygen()
    ct, r = elgamal.encrypt(h, vote)
    proof = zkp.or_prove(_stmts(ct, h), vote, r, "t", ["ctx"])
    assert zkp.or_verify(_stmts(ct, h), proof, "t", ["ctx"])


@pytest.mark.parametrize("vote", [2, 5, L - 1])   # L-1 is "-1"
def test_or_proof_soundness_for_invalid_votes(vote):
    _, h = elgamal.keygen()
    ct, r = elgamal.encrypt(h, vote)
    for pretend in (0, 1):
        proof = zkp.or_prove(_stmts(ct, h), pretend, r, "t", ["ctx"])
        assert not zkp.or_verify(_stmts(ct, h), proof, "t", ["ctx"])


def test_or_proof_is_bound_to_context_and_ciphertext():
    _, h = elgamal.keygen()
    ct, r = elgamal.encrypt(h, 1)
    proof = zkp.or_prove(_stmts(ct, h), 1, r, "t", ["voter-A"])
    assert not zkp.or_verify(_stmts(ct, h), proof, "t", ["voter-B"])       # replayed by another voter
    other, _ = elgamal.encrypt(h, 1)
    assert not zkp.or_verify(_stmts(other, h), proof, "t", ["voter-A"])    # moved to another ciphertext


def test_or_proof_tampering_detected():
    _, h = elgamal.keygen()
    ct, r = elgamal.encrypt(h, 0)
    proof = zkp.or_prove(_stmts(ct, h), 0, r, "t", [])
    proof["z"][1] = group.scalar_to_hex((group.scalar_from_hex(proof["z"][1]) + 1) % L)
    assert not zkp.or_verify(_stmts(ct, h), proof, "t", [])


def test_or_proof_branches_are_indistinguishable_in_form():
    """Both branches carry a (c, z) pair of uniformly random-looking scalars."""
    _, h = elgamal.keygen()
    ct, r = elgamal.encrypt(h, 1)
    proof = zkp.or_prove(_stmts(ct, h), 1, r, "t", [])
    assert len(proof["c"]) == len(proof["z"]) == 2


def test_schnorr_nizk():
    x, h = elgamal.keygen()
    proof = zkp.schnorr_nizk_prove(x, h, "k", ["e1"])
    assert zkp.schnorr_nizk_verify(h, proof, "k", ["e1"])
    assert not zkp.schnorr_nizk_verify(h, proof, "k", ["e2"])
    _, other = elgamal.keygen()
    assert not zkp.schnorr_nizk_verify(other, proof, "k", ["e1"])


def test_interactive_schnorr_login():
    s = group.random_scalar()
    y = base_mul(s)
    prover = zkp.SchnorrProver(s)
    c = zkp.new_login_challenge()
    z = prover.respond(c)
    assert zkp.schnorr_login_verify(y, prover.commitment, c, z)
    assert not zkp.schnorr_login_verify(y, prover.commitment, zkp.new_login_challenge(), z)
    with pytest.raises(RuntimeError):
        prover.respond(c)    # nonce is single-use


def test_schnorr_nonce_reuse_would_leak_the_secret():
    """Why the prover refuses to answer twice: two answers with one nonce reveal s."""
    s, k = group.random_scalar(), group.random_scalar()
    c1, c2 = group.random_scalar(), group.random_scalar()
    z1, z2 = (k + c1 * s) % L, (k + c2 * s) % L
    recovered = (z1 - z2) * pow(c1 - c2, -1, L) % L
    assert recovered == s


def test_decryption_proof():
    x, h = elgamal.keygen()
    ct = elgamal.aggregate(elgamal.encrypt(h, 1)[0] for _ in range(4))
    share = elgamal.decryption_share(x, ct)
    proof = zkp.dleq_prove((G, h, ct.a, share), x, "decryption", [0])
    assert zkp.dleq_verify((G, h, ct.a, share), proof, "decryption", [0])
    fake_share = sub(ct.b, base_mul(3))      # claim the total is 3 instead of 4
    fake_proof = zkp.dleq_prove((G, h, ct.a, fake_share), x, "decryption", [0])
    assert not zkp.dleq_verify((G, h, ct.a, fake_share), fake_proof, "decryption", [0])


# --------------------------------------------------------------- signing
def test_signatures_and_domain_separation():
    key = signing.generate()
    pub = signing.public_hex(key)
    env = signing.signed(key, "ballot", {"x": 1})
    assert signing.verify_signed(pub, "ballot", env)
    assert not signing.verify_signed(pub, "receipt", env)           # wrong domain
    env["body"]["x"] = 2
    assert not signing.verify_signed(pub, "ballot", env)            # modified body


# -------------------------------------------------------------- keystore
def test_keystore_round_trip_and_permissions(tmp_path):
    path = str(tmp_path / "k.key")
    keystore.save(path, {"secret": "abc"}, PASS, "test", FAST_KDF)
    assert keystore.load(path, PASS) == {"secret": "abc"}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert "abc" not in open(path).read()


def test_keystore_wrong_passphrase(tmp_path):
    path = str(tmp_path / "k.key")
    keystore.save(path, {"secret": "abc"}, PASS, "test", FAST_KDF)
    with pytest.raises(keystore.KeystoreError):
        keystore.load(path, "wrong passphrase!")


def test_keystore_tamper_and_downgrade_detected(tmp_path):
    path = str(tmp_path / "k.key")
    keystore.save(path, {"secret": "abc"}, PASS, "test", FAST_KDF)
    doc = json.load(open(path))
    doc["header"]["label"] = "evil"                                  # header is authenticated (AAD)
    json.dump(doc, open(path, "w"))
    with pytest.raises(keystore.KeystoreError):
        keystore.load(path, PASS)
    doc["header"]["label"] = "test"
    doc["header"]["kdf"]["memory_cost"] = 8                          # KDF downgrade
    json.dump(doc, open(path, "w"))
    with pytest.raises(keystore.KeystoreError):
        keystore.load(path, PASS)


# ----------------------------------------------------------------- board
def _chain(n):
    entries = []
    for i in range(n):
        entries.append(board.make_entry(i, board.head_hash(entries), "voter", {"n": i}, 1000 + i))
    return entries


def test_board_chain_ok():
    board.verify_chain(_chain(5))


@pytest.mark.parametrize("attack", ["modify", "delete", "reorder", "insert"])
def test_board_tampering_detected(attack):
    entries = _chain(5)
    if attack == "modify":
        entries[2]["payload"]["n"] = 99
    elif attack == "delete":
        del entries[2]
    elif attack == "reorder":
        entries[1], entries[2] = entries[2], entries[1]
    else:
        entries.insert(2, board.make_entry(2, entries[1]["hash"], "voter", {"n": "x"}, 1))
    with pytest.raises(board.BoardError):
        board.verify_chain(entries)
