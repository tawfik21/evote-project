"""Auditor: anyone can download the board and verify the whole election."""

import json

from evote.core.audit import AuditReport, audit_board


def fetch_board(transport) -> dict:
    return transport.get("/api/board")


def audit(trust: dict, board_data: dict) -> AuditReport:
    return audit_board(board_data["entries"], trust["authority_public_key"], trust["election_id"],
                       trust["server_public_key"], board_data.get("head"))


def save_board(board_data: dict, path: str) -> None:
    with open(path, "w") as fh:
        json.dump(board_data, fh, indent=2)


def load_board(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)
