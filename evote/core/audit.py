"""Independent verification of an entire bulletin board.

Anyone holding the trust bundle can run this: it trusts nothing the server
says and re-checks every hash, signature and zero-knowledge proof.
"""

from dataclasses import dataclass, field

from evote.core import protocol, signing
from evote.core.board import BoardError, verify_chain
from evote.core.protocol import ValidationError


@dataclass
class AuditReport:
    checks: list[tuple[bool, str]] = field(default_factory=list)
    manifest: dict | None = None
    voters: dict = field(default_factory=dict)          # voter_id -> enrolment body
    ballots: list = field(default_factory=list)         # (entry, envelope, ciphertexts)
    close: dict | None = None
    result: dict | None = None

    @property
    def ok(self) -> bool:
        return all(ok for ok, _ in self.checks)

    def passed(self, message: str) -> None:
        self.checks.append((True, message))

    def failed(self, message: str) -> None:
        self.checks.append((False, message))

    def ballot_ciphertexts(self):
        return [cts for _, _, cts in self.ballots]


def audit_board(entries: list[dict], authority_public_key: str, election_id: str | None = None,
                server_public_key: str | None = None, signed_head: dict | None = None) -> AuditReport:
    report = AuditReport()

    # 1. Hash chain ------------------------------------------------------------
    try:
        verify_chain(entries)
        report.passed(f"hash chain intact ({len(entries)} entries)")
    except BoardError as exc:
        report.failed(f"hash chain broken at {exc}")
        return report  # nothing after a broken link can be trusted

    # 2. Server's signature over the head ------------------------------------
    if signed_head is not None and server_public_key is not None:
        head_body = signed_head.get("body", {}) if isinstance(signed_head, dict) else {}
        if not signing.verify_signed(server_public_key, "board-head", signed_head):
            report.failed("board head signature from the server is invalid")
        elif head_body.get("head_hash") != (entries[-1]["hash"] if entries else None) \
                or head_body.get("length") != len(entries):
            report.failed("server-signed head does not match the board contents")
        else:
            report.passed("server signature on board head is valid")

    if not entries or entries[0].get("kind") != "election":
        report.failed("board does not start with an election manifest")
        return report

    # 3. Walk every entry ------------------------------------------------------
    voted: set[str] = set()
    close_hash = None
    for entry in entries:
        kind, payload, idx = entry["kind"], entry["payload"], entry["index"]
        try:
            if idx == 0:
                manifest = protocol.verify_manifest(payload, authority_public_key)
                if election_id is not None and manifest["election_id"] != election_id:
                    raise ValidationError("election id does not match the trust bundle")
                report.manifest = manifest
                report.passed(f"manifest signed by the authority; election key proof valid "
                              f"({len(manifest['candidates'])} candidates)")
                continue
            if kind == "election":
                raise ValidationError("second election manifest")
            manifest = report.manifest
            if close_hash is not None and kind in ("voter", "ballot"):
                raise ValidationError(f"{kind} entry appears after the election was closed")

            if kind == "voter":
                body = protocol.verify_enrolment(payload, manifest["election_id"])
                if body["voter_id"] in report.voters:
                    raise ValidationError(f"voter {body['voter_id']} enrolled twice")
                report.voters[body["voter_id"]] = body

            elif kind == "ballot":
                voter_id = payload.get("body", {}).get("voter_id")
                if voter_id not in report.voters:
                    raise ValidationError(f"ballot from un-enrolled voter {voter_id!r}")
                if voter_id in voted:
                    raise ValidationError(f"second ballot from voter {voter_id}")
                cts = protocol.verify_ballot(manifest, report.voters[voter_id]["sign_public_key"], payload)
                voted.add(voter_id)
                report.ballots.append((entry, payload, cts))

            elif kind == "close":
                if close_hash is not None:
                    raise ValidationError("election closed twice")
                close_hash = entry["hash"]     # the election is closed from here on, even if this entry is bad
                body = protocol.verify_close(payload, manifest)
                if body["head_hash"] != entry["prev_hash"]:
                    raise ValidationError("authority closed over a different board state")
                if body.get("ballot_count") != len(report.ballots):
                    raise ValidationError("ballot count at close does not match the board")
                report.close = body
                report.passed(f"election closed by the authority over {len(report.ballots)} ballots")

            elif kind == "result":
                if close_hash is None:
                    raise ValidationError("result published before the election was closed")
                if report.result is not None:
                    raise ValidationError("second result")
                report.result = protocol.verify_result(payload, manifest, report.ballot_ciphertexts(), close_hash)
                report.passed("result: aggregate recomputed, every decryption proof valid")
        except ValidationError as exc:
            report.failed(f"entry {idx} ({kind}): {exc}")

    if report.manifest is not None:
        report.passed(f"{len(report.voters)} enrolment(s) checked (signature + login-key proof)")
        report.passed(f"{len(report.ballots)} ballot(s) checked (signature + 0/1 proofs + sum proof), "
                      f"one per voter")
    return report
