"""Attack simulations for the live demo and for the test suite.

Each function plays a dishonest party and returns (blocked, explanation).
"blocked" is True when the system correctly stopped the attack.
"""

import copy
import json
import os
import sqlite3
import tempfile

from evote.clients import voter as voter_client
from evote.clients.api import HttpsTransport, ServerError, tls_error_types
from evote.core import board, elgamal, group, protocol, signing, tls, zkp
from evote.core.group import G, base_mul


def _rejected(exc: ServerError) -> tuple[bool, str]:
    return True, f"server rejected it ({exc.status}): {exc.message}"


# --------------------------------------------------------------------------
# Dishonest voter
# --------------------------------------------------------------------------

def build_malicious_ballot(manifest: dict, voter_id: str, votes: list[int], sign_key) -> dict:
    """Encrypt an arbitrary vote vector (e.g. [5, 0, 0]) and *try* to prove it valid.

    The prover pretends each entry is a 0 or a 1 and that the total is 1. The
    signature is genuine; only the zero-knowledge proofs are lies, and they
    cannot be made to verify without breaking the discrete-log problem.
    """
    election_id = manifest["election_id"]
    public = protocol.election_public_key(manifest)
    cts, proofs, rs = [], [], []
    for i, v in enumerate(votes):
        ct, r = elgamal.encrypt(public, v)
        statements = [protocol._encrypts_value(ct, public, 0), protocol._encrypts_value(ct, public, 1)]
        proofs.append(zkp.or_prove(statements, 1 if v else 0, r, "ballot-entry", [election_id, voter_id, i]))
        cts.append(ct)
        rs.append(r)
    total = elgamal.aggregate(cts)
    sum_proof = zkp.dleq_prove(protocol._encrypts_value(total, public, 1), sum(rs) % group.L,
                               "ballot-sum", [election_id, voter_id])
    body = {"election_id": election_id, "voter_id": voter_id, "ciphertexts": [c.to_json() for c in cts],
            "entry_proofs": proofs, "sum_proof": sum_proof}
    return signing.signed(sign_key, "ballot", body)


def overvote(transport, trust: dict, keys, weight: int = 5) -> tuple[bool, str]:
    """Try to cast `weight` votes for the first candidate in a single ballot."""
    manifest, _ = voter_client.fetch_manifest(transport, trust)
    votes = [weight] + [0] * (len(manifest["candidates"]) - 1)
    ballot = build_malicious_ballot(manifest, keys.voter_id, votes, keys.sign_key)
    token = voter_client.login(transport, keys)
    try:
        transport.post("/api/ballot", {"ballot": ballot}, token=token)
    except ServerError as exc:
        return _rejected(exc)
    return False, f"server ACCEPTED a ballot worth {weight} votes"


def double_vote(transport, trust: dict, keys, choice: str) -> tuple[bool, str]:
    """Vote, then try to vote again with a fresh login."""
    try:
        voter_client.vote(transport, trust, keys, choice)
    except ServerError:
        pass  # already voted earlier - fine, the second attempt below is the attack
    try:
        voter_client.vote(transport, trust, keys, choice)
    except ServerError as exc:
        return _rejected(exc)
    return False, "server accepted a second ballot from the same voter"


def copy_ballot(transport, trust: dict, keys) -> tuple[bool, str]:
    """Copy another voter's encrypted ballot and submit it as our own.

    If this worked, an attacker could duplicate a target's (unknown) vote and
    learn something about it from the final tally (a known attack on early
    Helios). The ZKPs are bound to the original voter id, so it fails.
    """
    entries = transport.get("/api/board")["entries"]
    victims = [e for e in entries if e["kind"] == "ballot" and e["payload"]["body"]["voter_id"] != keys.voter_id]
    if not victims:
        return False, "no other voter's ballot on the board to copy (cast one first)"
    stolen = copy.deepcopy(victims[0]["payload"]["body"])
    victim_id = stolen["voter_id"]
    stolen["voter_id"] = keys.voter_id
    forged = signing.signed(keys.sign_key, "ballot", stolen)      # genuine signature by the attacker
    token = voter_client.login(transport, keys)
    try:
        transport.post("/api/ballot", {"ballot": forged}, token=token)
    except ServerError as exc:
        blocked, msg = _rejected(exc)
        return blocked, f"copying {victim_id}'s ballot: {msg}"
    return False, "server accepted a copied ballot"


# --------------------------------------------------------------------------
# Network attacker
# --------------------------------------------------------------------------

def replay_login(transport, keys) -> tuple[bool, str]:
    """An eavesdropper records a complete login and tries to reuse it."""
    prover = zkp.SchnorrProver(keys.login_secret)
    commitment = group.point_to_hex(prover.commitment)
    step1 = transport.post("/api/login/commit", {"voter_id": keys.voter_id, "commitment": commitment})
    recorded = {"challenge_id": step1["challenge_id"],
                "response": group.scalar_to_hex(prover.respond(group.scalar_from_hex(step1["challenge"])))}
    transport.post("/api/login/respond", recorded)                  # the genuine login

    messages = []
    try:
        transport.post("/api/login/respond", recorded)              # replay #1: same challenge
        return False, "server accepted a replayed login response"
    except ServerError as exc:
        messages.append(f"replaying the old response: rejected ({exc.message})")
    step1b = transport.post("/api/login/commit", {"voter_id": keys.voter_id, "commitment": commitment})
    try:                                                            # replay #2: same T, new challenge
        transport.post("/api/login/respond", {"challenge_id": step1b["challenge_id"],
                                              "response": recorded["response"]})
        return False, "server accepted an old response to a new challenge"
    except ServerError as exc:
        messages.append(f"reusing old commitment+response on a fresh challenge: rejected ({exc.message})")
    return True, "; ".join(messages)


def fake_certificate(trust: dict) -> tuple[bool, str]:
    """Man-in-the-middle: the client sees a certificate other than the pinned one."""
    with tempfile.TemporaryDirectory() as tmp:
        pem = tls.generate_certificate(os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem"),
                                       "attacker-pass", ["localhost"], ["127.0.0.1"])
    fake_trust = dict(trust, tls_certificate_pem=pem)
    transport = HttpsTransport(fake_trust)
    try:
        transport.get("/api/election")
        return False, "client connected even though the certificate was not the pinned one"
    except tls_error_types() as exc:
        return True, f"client refused the connection: certificate verification failed ({type(exc).__name__})"
    finally:
        transport.close()


# --------------------------------------------------------------------------
# Dishonest server operator / database administrator
# --------------------------------------------------------------------------

def tamper_database(db_path: str) -> tuple[bool, str]:
    """Flip a voter's ballot inside the server database and rebuild the hash chain.

    This is the strongest insider attack: the chain is recomputed so it looks
    intact. It is still caught because the voter's Ed25519 signature no longer
    matches, and because the voter's receipt holds the old entry hash.
    Returns (done, message); run `evote audit` / `evote voter check` afterwards.
    """
    conn = sqlite3.connect(db_path, isolation_level=None)
    rows = conn.execute("SELECT idx, entry_json FROM board ORDER BY idx").fetchall()
    entries = [json.loads(r[1]) for r in rows]
    target = next((e for e in entries if e["kind"] == "ballot"), None)
    if target is None:
        return False, "no ballot in the database to tamper with"
    cts = target["payload"]["body"]["ciphertexts"]
    # Swap the encrypted entries of the first two candidates (moves the vote).
    cts[0], cts[1] = cts[1], cts[0]
    prev = board.GENESIS_HASH
    conn.execute("BEGIN")
    for e in entries:
        e["prev_hash"] = prev
        e["hash"] = board.compute_hash(e)
        conn.execute("UPDATE board SET entry_json=?, entry_hash=? WHERE idx=?",
                     (json.dumps(e, sort_keys=True), e["hash"], e["index"]))
        prev = e["hash"]
    conn.execute("COMMIT")
    conn.close()
    return True, (f"swapped candidates in {target['payload']['body']['voter_id']}'s ballot (entry "
                  f"{target['index']}) and rebuilt the whole hash chain; now run 'evote audit'")


# --------------------------------------------------------------------------
# Dishonest authority
# --------------------------------------------------------------------------

def fake_result(board_entries: list[dict], trust: dict, elgamal_secret: int, authority_key,
                shift_from: int = 0, shift_to: int = 1) -> tuple[bool, str]:
    """The authority (who holds the real key!) moves one vote and tries to prove it."""
    from evote.core.audit import audit_board

    report = audit_board(board_entries, trust["authority_public_key"], trust["election_id"])
    if report.close is None:
        return False, "close the election first"
    close_hash = next(e["hash"] for e in board_entries if e["kind"] == "close")
    honest = protocol.compute_result(report.manifest, elgamal_secret, report.ballot_ciphertexts(),
                                     close_hash, authority_key)["body"]
    body = copy.deepcopy(honest)
    if body["counts"][shift_from] == 0:
        shift_from, shift_to = shift_to, shift_from
    body["counts"][shift_from] -= 1
    body["counts"][shift_to] += 1
    # Best possible cheat: make the share consistent with the fake count (D' = B - count'*G)
    # and run the DLEQ prover with the real secret key. It still cannot be valid.
    public = protocol.election_public_key(report.manifest)
    for i in (shift_from, shift_to):
        agg = elgamal.Ciphertext.from_json(body["aggregate"][i])
        fake_share = group.sub(agg.b, base_mul(body["counts"][i]))
        body["decryption_shares"][i] = group.point_to_hex(fake_share)
        body["decryption_proofs"][i] = zkp.dleq_prove((G, public, agg.a, fake_share), elgamal_secret,
                                                      "decryption", [report.manifest["election_id"], i])
    forged = signing.signed(authority_key, "result", body)
    try:
        protocol.verify_result(forged, report.manifest, report.ballot_ciphertexts(), close_hash)
    except protocol.ValidationError as exc:
        return True, f"real counts {honest['counts']}, claimed {body['counts']}: verifier says '{exc}'"
    return False, "a false result verified"
