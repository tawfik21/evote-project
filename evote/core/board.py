"""The public bulletin board: an append-only, hash-chained log.

Each entry stores the hash of the previous entry:

    hash_i = SHA-256("evote/v1/board-entry" || canonical(index, prev_hash, kind, timestamp, payload))

Changing, deleting, inserting or reordering any entry changes every later
hash. The server signs the latest hash (the "head") and every receipt it
hands to a voter contains the hash of that voter's entry, so a server that
rewrites history is caught by the voters' receipts and by the voters' own
signatures on their ballots, which the server cannot forge.
"""

from evote.core.encoding import sha256_hex

GENESIS_HASH = "0" * 64

KINDS = ("election", "voter", "ballot", "close", "result")


class BoardError(ValueError):
    def __init__(self, index: int, reason: str):
        super().__init__(f"entry {index}: {reason}")
        self.index = index
        self.reason = reason


def compute_hash(entry: dict) -> str:
    content = {k: entry[k] for k in ("index", "prev_hash", "kind", "timestamp", "payload")}
    return sha256_hex("board-entry", content)


def make_entry(index: int, prev_hash: str, kind: str, payload: dict, timestamp: int) -> dict:
    if kind not in KINDS:
        raise ValueError(f"unknown entry kind {kind}")
    entry = {"index": index, "prev_hash": prev_hash, "kind": kind, "timestamp": timestamp, "payload": payload}
    entry["hash"] = compute_hash(entry)
    return entry


def head_hash(entries: list[dict]) -> str:
    return entries[-1]["hash"] if entries else GENESIS_HASH


def verify_chain(entries: list[dict]) -> None:
    """Raise BoardError at the first entry that breaks the chain."""
    prev = GENESIS_HASH
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BoardError(position, "entry is not an object")
        if entry.get("index") != position:
            raise BoardError(position, "index out of sequence (entry inserted, deleted or reordered)")
        if entry.get("prev_hash") != prev:
            raise BoardError(position, "prev_hash does not match the previous entry")
        try:
            recomputed = compute_hash(entry)
        except KeyError as exc:
            raise BoardError(position, f"missing field {exc}") from exc
        if entry.get("hash") != recomputed:
            raise BoardError(position, "stored hash does not match the entry contents (entry modified)")
        prev = recomputed
