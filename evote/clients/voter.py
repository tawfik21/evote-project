"""Voter client: enrol, log in with a Schnorr ZKP, cast a ballot, check the receipt."""

import os
from dataclasses import dataclass

from evote.core import board, group, keystore, protocol, signing, zkp


class ClientError(Exception):
    pass


@dataclass
class VoterKeys:
    voter_id: str
    election_id: str
    sign_key: object          # Ed25519 private key (ballot signatures)
    login_secret: int         # Schnorr secret s; login public key is s*G


def fetch_manifest(transport, trust: dict) -> tuple[dict, str]:
    """Download the manifest and verify it against the *pinned* authority key."""
    data = transport.get("/api/election")
    try:
        manifest = protocol.verify_manifest(data["manifest"], trust["authority_public_key"])
    except protocol.ValidationError as exc:
        raise ClientError(f"server sent an invalid election manifest: {exc}") from exc
    if manifest["election_id"] != trust["election_id"]:
        raise ClientError("server is running a different election than the trust bundle says")
    return manifest, data["state"]


def enrol(transport, trust: dict, voter_id: str, code: str, keyfile: str, passphrase: str,
          kdf_params: dict | None = None) -> dict:
    if os.path.exists(keyfile):
        raise ClientError(f"{keyfile} already exists; refusing to overwrite a key file")
    manifest, _ = fetch_manifest(transport, trust)
    sign_key = signing.generate()
    login_secret = group.random_scalar()
    request = protocol.create_enrolment_request(manifest["election_id"], voter_id, sign_key, login_secret)
    # Save the keys first (encrypted) so a crash after enrolment cannot lose them.
    keystore.save(keyfile, {"voter_id": voter_id, "election_id": manifest["election_id"],
                            "ed25519": signing.private_to_hex(sign_key),
                            "schnorr": group.scalar_to_hex(login_secret)}, passphrase, "voter", kdf_params)
    try:
        return transport.post("/api/enrol", {"code": code, "enrolment": request})
    except Exception:
        os.unlink(keyfile)
        raise


def load_keys(keyfile: str, passphrase: str) -> VoterKeys:
    data = keystore.load(keyfile, passphrase)
    return VoterKeys(data["voter_id"], data["election_id"], signing.private_from_hex(data["ed25519"]),
                     group.scalar_from_hex(data["schnorr"]))


def login(transport, keys: VoterKeys) -> str:
    """Interactive Schnorr identification. The secret never leaves this machine."""
    prover = zkp.SchnorrProver(keys.login_secret)
    step1 = transport.post("/api/login/commit", {"voter_id": keys.voter_id,
                                                  "commitment": group.point_to_hex(prover.commitment)})
    challenge = group.scalar_from_hex(step1["challenge"])
    response = prover.respond(challenge)
    step2 = transport.post("/api/login/respond", {"challenge_id": step1["challenge_id"],
                                                   "response": group.scalar_to_hex(response)})
    return step2["session_token"]


def resolve_choice(manifest: dict, choice: str) -> int:
    candidates = manifest["candidates"]
    if choice in candidates:
        return candidates.index(choice)
    lowered = [c.lower() for c in candidates]
    if choice.lower() in lowered:
        return lowered.index(choice.lower())
    if choice.isdigit() and 1 <= int(choice) <= len(candidates):
        return int(choice) - 1
    raise ClientError(f"unknown candidate {choice!r}; choose one of: {', '.join(candidates)}")


def verify_receipt(trust: dict, receipt: dict, voter_id: str | None = None, ballot: dict | None = None) -> dict:
    if not signing.verify_signed(trust["server_public_key"], "receipt", receipt):
        raise ClientError("receipt signature is invalid")
    body = receipt["body"]
    if body["election_id"] != trust["election_id"]:
        raise ClientError("receipt is for another election")
    if voter_id is not None and body["voter_id"] != voter_id:
        raise ClientError("receipt is for another voter")
    if ballot is not None and body["tracker"] != protocol.ballot_tracker(ballot):
        raise ClientError("receipt tracker does not match the ballot we sent")
    return body


def vote(transport, trust: dict, keys: VoterKeys, choice: str) -> tuple[dict, dict]:
    manifest, state = fetch_manifest(transport, trust)
    if state != "open":
        raise ClientError(f"election is {state}, not open")
    index = resolve_choice(manifest, choice)
    token = login(transport, keys)
    ballot = protocol.create_ballot(manifest, keys.voter_id, index, keys.sign_key)
    receipt = transport.post("/api/ballot", {"ballot": ballot}, token=token)["receipt"]
    verify_receipt(trust, receipt, keys.voter_id, ballot)
    return receipt, ballot


def check_receipt(transport, trust: dict, receipt: dict) -> list[tuple[bool, str]]:
    """'Recorded as cast': is my ballot on the public board, unchanged, where the server said?"""
    results = []
    try:
        body = verify_receipt(trust, receipt)
        results.append((True, "receipt is signed by the ballot server"))
    except ClientError as exc:
        return [(False, str(exc))]
    data = transport.get("/api/board")
    entries = data["entries"]
    try:
        board.verify_chain(entries)
        results.append((True, f"board hash chain intact ({len(entries)} entries)"))
    except board.BoardError as exc:
        results.append((False, f"board hash chain broken: {exc}"))
    idx = body["index"]
    if idx >= len(entries):
        results.append((False, f"board has no entry {idx}: my ballot has been removed"))
        return results
    entry = entries[idx]
    if entry["hash"] != body["entry_hash"]:
        results.append((False, f"entry {idx} has changed since my receipt was issued"))
    elif entry["kind"] != "ballot" or protocol.ballot_tracker(entry["payload"]) != body["tracker"]:
        results.append((False, f"entry {idx} is not my ballot"))
    else:
        results.append((True, f"my ballot is on the board at entry {idx} (tracker {body['tracker'][:16]})"))
    return results
