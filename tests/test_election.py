"""End-to-end election through the real server code (Flask test client) + attack simulations."""

import random

import pytest

from evote.clients import attacks, auditor, authority, voter
from evote.clients.api import ServerError
from evote.core import group, protocol, zkp

from conftest import CANDIDATES, PASS, enrol


def run_full_election(e, n_voters=8, seed=1):
    rng = random.Random(seed)
    truth = [0] * len(CANDIDATES)
    receipts = []
    for i in range(1, n_voters + 1):
        keys = enrol(e, f"v{i}")
        choice = rng.randrange(len(CANDIDATES))
        truth[choice] += 1
        receipt, _ = voter.vote(e.transport, e.trust, keys, CANDIDATES[choice])
        receipts.append(receipt)
    authority.close(e.transport, e.trust, e.authority_key, PASS)
    result = authority.tally(e.transport, e.trust, e.authority_key, PASS)
    return truth, result, receipts


def test_full_election_tally_is_correct_and_audit_passes(election):
    truth, result, receipts = run_full_election(election)
    assert result["counts"] == truth
    report = auditor.audit(election.trust, auditor.fetch_board(election.transport))
    assert report.ok, report.checks
    assert report.result["counts"] == truth
    for receipt in receipts:
        assert all(ok for ok, _ in voter.check_receipt(election.transport, election.trust, receipt))


def test_election_with_no_votes(election):
    authority.close(election.transport, election.trust, election.authority_key, PASS)
    result = authority.tally(election.transport, election.trust, election.authority_key, PASS)
    assert result["counts"] == [0, 0, 0]


def test_server_never_sees_plaintext_votes(election):
    keys = enrol(election, "v1")
    _, ballot = voter.vote(election.transport, election.trust, keys, "Bob")
    stored = auditor.fetch_board(election.transport)["entries"][-1]["payload"]
    assert stored == ballot
    assert "Bob" not in str(stored["body"]) and set(stored["body"]) == {
        "election_id", "voter_id", "ciphertexts", "entry_proofs", "sum_proof"}


# ------------------------------------------------------------- enrolment
def test_enrolment_wrong_code_rejected(election):
    election.codes["v1"] = "AAAA-BBBB-CCCC-DDDD"
    with pytest.raises(ServerError) as exc:
        enrol(election, "v1")
    assert exc.value.status == 403


def test_enrolment_code_single_use(election, tmp_path):
    enrol(election, "v1")
    with pytest.raises(ServerError) as exc:
        voter.enrol(election.transport, election.trust, "v1", election.codes["v1"], str(tmp_path / "again.key"), PASS)
    assert exc.value.status == 409 and "already" in exc.value.message


def test_unknown_voter_cannot_enrol(election):
    election.codes["mallory"] = election.codes["v1"]
    with pytest.raises(ServerError):
        enrol(election, "mallory")


# ----------------------------------------------------------------- login
def test_login_with_wrong_secret_fails(election):
    keys = enrol(election, "v1")
    keys.login_secret = group.random_scalar()
    with pytest.raises(ServerError) as exc:
        voter.login(election.transport, keys)
    assert exc.value.status == 403


def test_login_replay_blocked(election):
    keys = enrol(election, "v1")
    blocked, msg = attacks.replay_login(election.transport, keys)
    assert blocked, msg


def test_lockout_after_repeated_failures(election):
    keys = enrol(election, "v1")
    good = keys.login_secret
    keys.login_secret = group.random_scalar()
    for _ in range(5):
        with pytest.raises(ServerError):
            voter.login(election.transport, keys)
    keys.login_secret = good
    with pytest.raises(ServerError) as exc:
        voter.login(election.transport, keys)
    assert exc.value.status == 429


def test_ballot_requires_session_and_token_is_single_use(election):
    keys = enrol(election, "v1")
    manifest, _ = voter.fetch_manifest(election.transport, election.trust)
    ballot = protocol.create_ballot(manifest, "v1", 0, keys.sign_key)
    with pytest.raises(ServerError) as exc:
        election.transport.post("/api/ballot", {"ballot": ballot})
    assert exc.value.status == 401
    token = voter.login(election.transport, keys)
    election.transport.post("/api/ballot", {"ballot": ballot}, token=token)
    with pytest.raises(ServerError) as exc:
        election.transport.post("/api/ballot", {"ballot": ballot}, token=token)
    assert exc.value.status == 401


def test_cannot_vote_as_someone_else(election):
    a = enrol(election, "v1")
    enrol(election, "v2")
    manifest, _ = voter.fetch_manifest(election.transport, election.trust)
    ballot = protocol.create_ballot(manifest, "v2", 0, a.sign_key)   # v1 logged in, ballot claims v2
    token = voter.login(election.transport, a)
    with pytest.raises(ServerError) as exc:
        election.transport.post("/api/ballot", {"ballot": ballot}, token=token)
    assert exc.value.status == 403


# --------------------------------------------------------------- attacks
def test_overvote_rejected_by_zkp(election):
    keys = enrol(election, "v1")
    blocked, msg = attacks.overvote(election.transport, election.trust, keys, 5)
    assert blocked and "proof" in msg


def test_negative_vote_rejected_by_zkp(election):
    keys = enrol(election, "v1")
    manifest, _ = voter.fetch_manifest(election.transport, election.trust)
    # +2 for Alice, -1 for Bob: still sums to 1, so only the per-entry 0/1 proofs catch it.
    ballot = attacks.build_malicious_ballot(manifest, "v1", [2, group.L - 1, 0], keys.sign_key)
    token = voter.login(election.transport, keys)
    with pytest.raises(ServerError) as exc:
        election.transport.post("/api/ballot", {"ballot": ballot}, token=token)
    assert "0-or-1 proof" in exc.value.message


def test_empty_ballot_rejected_by_sum_proof(election):
    keys = enrol(election, "v1")
    manifest, _ = voter.fetch_manifest(election.transport, election.trust)
    ballot = attacks.build_malicious_ballot(manifest, "v1", [0, 0, 0], keys.sign_key)
    token = voter.login(election.transport, keys)
    with pytest.raises(ServerError) as exc:
        election.transport.post("/api/ballot", {"ballot": ballot}, token=token)
    assert "exactly-one-vote" in exc.value.message


def test_double_vote_rejected(election):
    keys = enrol(election, "v1")
    blocked, msg = attacks.double_vote(election.transport, election.trust, keys, "Alice")
    assert blocked and "already voted" in msg


def test_copied_ballot_rejected(election):
    victim = enrol(election, "v1")
    voter.vote(election.transport, election.trust, victim, "Carol")
    attacker = enrol(election, "v2")
    blocked, msg = attacks.copy_ballot(election.transport, election.trust, attacker)
    assert blocked, msg


def test_vote_after_close_rejected(election):
    keys = enrol(election, "v1")
    authority.close(election.transport, election.trust, election.authority_key, PASS)
    with pytest.raises(Exception):
        voter.vote(election.transport, election.trust, keys, "Alice")


def test_close_requires_authority_signature(election):
    from evote.core import signing
    impostor = signing.generate()
    entries = auditor.fetch_board(election.transport)["entries"]
    env = protocol.create_close(impostor, election.trust["election_id"], entries[-1]["hash"], 0)
    with pytest.raises(ServerError) as exc:
        election.transport.post("/api/close", {"close": env})
    assert exc.value.status == 403


def test_database_tampering_detected_by_audit_and_receipt(election):
    keys = enrol(election, "v1")
    receipt, _ = voter.vote(election.transport, election.trust, keys, "Alice")
    done, _ = attacks.tamper_database(election.db)
    assert done
    report = auditor.audit(election.trust, auditor.fetch_board(election.transport))
    assert not report.ok
    assert any("signature" in msg for ok, msg in report.checks if not ok)
    results = voter.check_receipt(election.transport, election.trust, receipt)
    assert not all(ok for ok, _ in results)


def test_fake_result_rejected(election):
    run_full_election(election, n_voters=4)
    from evote.core import keystore
    from evote.core.signing import private_from_hex
    data = keystore.load(election.authority_key, PASS)
    blocked, msg = attacks.fake_result(auditor.fetch_board(election.transport)["entries"], election.trust,
                                       group.scalar_from_hex(data["elgamal_secret"]),
                                       private_from_hex(data["ed25519"]))
    assert blocked, msg


def test_server_rejects_wrong_result(election):
    run_full_election(election, n_voters=3)
    # A second, *altered* result submitted directly is refused by state + verification.
    with pytest.raises(ServerError):
        election.transport.post("/api/result", {"result": {"body": {}, "signature": "00"}})


def test_offline_board_copy_audit(election, tmp_path):
    run_full_election(election, n_voters=3)
    data = auditor.fetch_board(election.transport)
    path = str(tmp_path / "board.json")
    auditor.save_board(data, path)
    assert auditor.audit(election.trust, auditor.load_board(path)).ok
    ballot = next(e for e in data["entries"] if e["kind"] == "ballot")
    cts = ballot["payload"]["body"]["ciphertexts"]
    cts[0], cts[1] = cts[1], cts[0]
    assert not auditor.audit(election.trust, data).ok
