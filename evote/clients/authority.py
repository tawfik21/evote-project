"""Election authority: set up the election, close it, and tally it.

The authority's ElGamal secret key lives only in an encrypted key file on the
authority's machine. It is used exactly once, to decrypt the *aggregate* of
all ballots after the election has closed.
"""

import json
import os

from evote.core import elgamal, group, keystore, protocol, signing
from evote.core.audit import audit_board
from evote.core.keystore import write_private_file
from evote.clients.voter import ClientError


def setup(out_dir: str, title: str, candidates: list[str], voter_ids: list[str], passphrase: str,
          kdf_params: dict | None = None) -> tuple[dict, dict]:
    os.makedirs(out_dir, exist_ok=True)
    keyfile = os.path.join(out_dir, "authority.key")
    if os.path.exists(keyfile):
        raise ClientError(f"{keyfile} already exists; refusing to overwrite")
    if len(set(voter_ids)) != len(voter_ids) or not voter_ids:
        raise ClientError("voter ids must be unique and non-empty")

    elgamal_secret, elgamal_public = elgamal.keygen()
    authority_key = signing.generate()
    manifest_env = protocol.create_manifest(title, candidates, elgamal_secret, elgamal_public, authority_key)
    election_id = manifest_env["body"]["election_id"]

    codes = {vid: protocol.new_enrolment_code() for vid in voter_ids}
    codes_env = signing.signed(authority_key, "enrolment-codes", {
        "election_id": election_id,
        "code_hashes": {vid: protocol.enrolment_code_hash(election_id, vid, code) for vid, code in codes.items()},
    })

    keystore.save(keyfile, {"election_id": election_id, "elgamal_secret": group.scalar_to_hex(elgamal_secret),
                            "ed25519": signing.private_to_hex(authority_key)}, passphrase, "authority", kdf_params)
    package = {"manifest": manifest_env, "enrolment_codes": codes_env}
    with open(os.path.join(out_dir, "election_package.json"), "w") as fh:
        json.dump(package, fh, indent=2)
    lines = ["# One-time enrolment codes. Give each voter ONLY their own code, privately.", ""]
    lines += [f"{vid}\t{code}" for vid, code in codes.items()]
    write_private_file(os.path.join(out_dir, "enrolment_codes.txt"), ("\n".join(lines) + "\n").encode())
    return package, codes


def load_keys(keyfile: str, passphrase: str) -> tuple[int, object, str]:
    data = keystore.load(keyfile, passphrase)
    return group.scalar_from_hex(data["elgamal_secret"]), signing.private_from_hex(data["ed25519"]), data["election_id"]


def _audited_board(transport, trust: dict):
    data = transport.get("/api/board")
    report = audit_board(data["entries"], trust["authority_public_key"], trust["election_id"],
                         trust["server_public_key"], data["head"])
    if not report.ok:
        failures = "; ".join(msg for ok, msg in report.checks if not ok)
        raise ClientError(f"the board failed its audit, refusing to continue: {failures}")
    return data["entries"], report


def close(transport, trust: dict, keyfile: str, passphrase: str) -> dict:
    _, authority_key, election_id = load_keys(keyfile, passphrase)
    entries, report = _audited_board(transport, trust)
    if report.close is not None:
        raise ClientError("election is already closed")
    envelope = protocol.create_close(authority_key, election_id, entries[-1]["hash"], len(report.ballots))
    return transport.post("/api/close", {"close": envelope})


def tally(transport, trust: dict, keyfile: str, passphrase: str) -> dict:
    elgamal_secret, authority_key, _ = load_keys(keyfile, passphrase)
    entries, report = _audited_board(transport, trust)
    if report.close is None:
        raise ClientError("close the election before tallying")
    if report.result is not None:
        raise ClientError("the result has already been published")
    result = protocol.compute_result(report.manifest, elgamal_secret, report.ballot_ciphertexts(),
                                     entries[-1]["hash"], authority_key)
    transport.post("/api/result", {"result": result})
    return result["body"]
