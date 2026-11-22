"""Step-by-step 'what happens behind the scenes' output for the demo.

`evote voter vote --explain` and `evote authority tally --explain` call these
instead of the quiet versions. They run exactly the same protocol and print
the real values at every step (shortened), and re-check every proof locally
so you can see each equation hold.
"""

import os
import sys

from evote.clients import authority, voter
from evote.core import elgamal, group, protocol, signing, zkp
from evote.core.encoding import canonical_json
from evote.core.group import G, add, base_mul, smul

COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if COLOUR else text


def short(value: str, n: int = 16) -> str:
    return value[:n] + "..." if len(value) > n else value


def step(title: str) -> None:
    print("\n" + _c(f"--- {title} ", "1;35") + _c("-" * max(0, 66 - len(title)), "35"))


def line(label: str, value="") -> None:
    print(f"  {label:<44} {_c(str(value), '36')}")


def note(text: str) -> None:
    print("  " + _c("> " + text, "33"))


def check(label: str, ok: bool) -> None:
    print(f"  {label:<44} " + (_c("TRUE", "1;32") if ok else _c("FALSE", "1;31")))


# ==========================================================================
# Voting
# ==========================================================================

def vote(transport, trust: dict, keys, choice: str):
    # 1 -------------------------------------------------------------------
    step("1. Download and verify the election manifest")
    manifest, state = voter.fetch_manifest(transport, trust)
    line("election", f"{manifest['title']}  ({short(manifest['election_id'])})")
    line("candidates", ", ".join(manifest["candidates"]))
    line("election public key  H = x*G", short(manifest["elgamal_public_key"]))
    check("authority signature valid (pinned key)?", True)
    check("Schnorr proof: authority knows x?", True)
    note("x (the decryption key) is on the authority's offline machine, NOT on the server")
    if state != "open":
        raise voter.ClientError(f"election is {state}, not open")
    index = voter.resolve_choice(manifest, choice)

    # 2 -------------------------------------------------------------------
    step("2. Log in: interactive Schnorr zero-knowledge proof")
    login_public = base_mul(keys.login_secret)
    line("your login public key   Y = s*G", short(login_public.hex()))
    note("your secret s never leaves your key file; you only prove you know it")
    prover = zkp.SchnorrProver(keys.login_secret)
    line("--> commitment  T = k*G   (k random)", short(prover.commitment.hex()))
    r1 = transport.post("/api/login/commit", {"voter_id": keys.voter_id,
                                               "commitment": prover.commitment.hex()})
    challenge = group.scalar_from_hex(r1["challenge"])
    line("<-- server's random challenge  c", short(r1["challenge"]))
    response = prover.respond(challenge)
    line("--> response  z = k + c*s", short(group.scalar_to_hex(response)))
    check("server checks  z*G == T + c*Y ?",
          base_mul(response) == add(prover.commitment, smul(challenge, login_public)))
    r2 = transport.post("/api/login/respond", {"challenge_id": r1["challenge_id"],
                                                "response": group.scalar_to_hex(response)})
    token = r2["session_token"]
    line("<-- session token (1 ballot, 5 min)", short(token, 12))
    note("k was destroyed: reusing it for a second challenge would reveal s")

    # 3 -------------------------------------------------------------------
    step("3. Encrypt the vote: exponential ElGamal, one ciphertext per candidate")
    vector = [1 if i == index else 0 for i in range(len(manifest["candidates"]))]
    line("your vote as a one-hot vector", vector)
    ballot = protocol.create_ballot(manifest, keys.voter_id, index, keys.sign_key)
    body = ballot["body"]
    for name, v, ct in zip(manifest["candidates"], vector, body["ciphertexts"]):
        print(f"  {name:<10} v={v}   A = r*G = {_c(short(ct['a'], 12), '36')}   "
              f"B = {v}*G + r*H = {_c(short(ct['b'], 12), '36')}")
    note("every entry uses fresh randomness r, so a 1 and a 0 look equally random")
    note("the randomness r is thrown away now, so you cannot later prove your vote to anyone")

    # 4 -------------------------------------------------------------------
    step("4. Zero-knowledge proofs that the ballot is valid")
    public = protocol.election_public_key(manifest)
    cts = [elgamal.Ciphertext.from_json(c) for c in body["ciphertexts"]]
    for i, (name, ct, proof) in enumerate(zip(manifest["candidates"], cts, body["entry_proofs"])):
        statements = [protocol._encrypts_value(ct, public, 0), protocol._encrypts_value(ct, public, 1)]
        ok = zkp.or_verify(statements, proof, "ballot-entry", [manifest["election_id"], keys.voter_id, i])
        print(f"  OR-proof {name:<10} c0={_c(short(proof['c'][0], 8), '36')} c1={_c(short(proof['c'][1], 8), '36')}"
              f"  '0 OR 1' verifies: " + (_c("TRUE", "1;32") if ok else _c("FALSE", "1;31")))
    note("one branch is real and one is simulated; nobody can tell which, so the vote stays secret")
    total = elgamal.aggregate(cts)
    ok = zkp.dleq_verify(protocol._encrypts_value(total, public, 1), body["sum_proof"], "ballot-sum",
                         [manifest["election_id"], keys.voter_id])
    line("sum of all ciphertexts  A_sum", short(total.a.hex(), 12))
    check("DLEQ proof: the sum encrypts exactly 1?", ok)
    note("a ballot with 5 votes, -1 votes or no vote cannot produce these proofs")

    # 5 -------------------------------------------------------------------
    step("5. Sign the ballot (Ed25519: non-repudiation)")
    line("your signing public key", short(signing.public_hex(keys.sign_key)))
    line("Ed25519 signature", short(ballot["signature"], 24))
    line("ballot size", f"{len(canonical_json(ballot))} bytes")
    line("tracking code = SHA-256(ballot)", short(protocol.ballot_tracker(ballot)))

    # 6 -------------------------------------------------------------------
    step("6. Send over TLS 1.3 (pinned certificate); server verifies and records")
    receipt = transport.post("/api/ballot", {"ballot": ballot}, token=token)["receipt"]
    rbody = voter.verify_receipt(trust, receipt, keys.voter_id, ballot)
    note("server checked: token, signature, every OR-proof, the sum proof, not already voted")
    line("<-- receipt: board position", rbody["index"])
    line("<-- receipt: entry hash", short(rbody["entry_hash"]))
    check("receipt signed by the server?", True)
    check("receipt tracker matches my ballot?", True)

    # 7 -------------------------------------------------------------------
    step("7. Your entry on the public bulletin board")
    entries = transport.get("/api/board")["entries"]
    entry = entries[rbody["index"]]
    line(f"entry {entry['index']}  kind", entry["kind"])
    line("prev_hash (= hash of entry before it)", short(entry["prev_hash"]))
    check("prev_hash links to previous entry?", entry["prev_hash"] == entries[entry["index"] - 1]["hash"])
    line("hash of this entry", short(entry["hash"]))
    note("changing ANY earlier entry would change this hash, and your receipt would expose it")

    step("Summary")
    note("the server stored:  ciphertexts, proofs, your signature, your voter id")
    note("the server NEVER saw: your choice, your secret keys, the randomness r")
    note("individual ballots are never decrypted, only the final totals are")
    return receipt, ballot


# ==========================================================================
# Tally
# ==========================================================================

def tally(transport, trust: dict, keyfile: str, passphrase: str) -> dict:
    secret, authority_key, _ = authority.load_keys(keyfile, passphrase)

    step("1. Download the board and audit everything first")
    entries, report = authority._audited_board(transport, trust)
    if report.close is None:
        raise voter.ClientError("close the election before tallying")
    if report.result is not None:
        raise voter.ClientError("the result has already been published")
    manifest = report.manifest
    ballots = report.ballot_ciphertexts()
    line("ballots on the board", len(ballots))
    check("every signature and ZKP valid?", report.ok)

    step("2. Add up ALL ballots while still encrypted (homomorphic)")
    note("(A1,B1) + (A2,B2) + ... = encryption of (v1 + v2 + ...)")
    result = protocol.compute_result(manifest, secret, ballots, entries[-1]["hash"], authority_key)
    body = result["body"]
    for name, agg in zip(manifest["candidates"], body["aggregate"]):
        print(f"  {name:<10} A_total = {_c(short(agg['a'], 12), '36')}   B_total = {_c(short(agg['b'], 12), '36')}")

    step("3. Decrypt ONLY the totals with the secret key x")
    public = protocol.election_public_key(manifest)
    for i, (name, agg_json) in enumerate(zip(manifest["candidates"], body["aggregate"])):
        agg = elgamal.Ciphertext.from_json(agg_json)
        share = bytes.fromhex(body["decryption_shares"][i]) if body["decryption_shares"][i] != group.IDENTITY.hex() \
            else group.IDENTITY
        print(f"  {name:<10} D = x*A_total = {_c(short(share.hex(), 12), '36')}   "
              f"B_total - D = m*G  ->  search m = {_c(body['counts'][i], '1;32')}")
    note("no single ballot was decrypted at any point")

    step("4. Prove each decryption is honest (Chaum-Pedersen DLEQ)")
    note("statement: log_G(H) == log_A(D), i.e. the same x was used, without revealing x")
    for i, (name, agg_json) in enumerate(zip(manifest["candidates"], body["aggregate"])):
        agg = elgamal.Ciphertext.from_json(agg_json)
        share = group.IDENTITY if body["decryption_shares"][i] == group.IDENTITY.hex() \
            else bytes.fromhex(body["decryption_shares"][i])
        ok = zkp.dleq_verify((G, public, agg.a, share), body["decryption_proofs"][i], "decryption",
                             [manifest["election_id"], i])
        check(f"decryption proof for {name}?", ok)

    step("5. Sign and publish the result")
    transport.post("/api/result", {"result": result})
    line("authority Ed25519 signature", short(result["signature"], 24))
    for name, count in zip(body["candidates"], body["counts"]):
        line(name, count)
    note("anyone can now run 'evote audit' to recompute the totals and check every proof")
    return body
