"""SQLite storage for the ballot server.

The bulletin board table is the public record. The other tables hold
server-side working state (hashed enrolment codes, single-use login
challenges, hashed session tokens) that is never published.
"""

import json
import sqlite3

from evote.core.board import head_hash, make_entry

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS board (
    idx INTEGER PRIMARY KEY, kind TEXT NOT NULL, entry_json TEXT NOT NULL, entry_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrolment_codes (
    voter_id TEXT PRIMARY KEY, code_hash TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS voters (
    voter_id TEXT PRIMARY KEY, sign_public_key TEXT NOT NULL, login_public_key TEXT NOT NULL,
    has_voted INTEGER NOT NULL DEFAULT 0, failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY, voter_id TEXT NOT NULL, commitment TEXT NOT NULL,
    challenge TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, voter_id TEXT NOT NULL, expires INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    # -- transactions -------------------------------------------------------
    def begin(self):
        self.conn.execute("BEGIN IMMEDIATE")

    def commit(self):
        self.conn.execute("COMMIT")

    def rollback(self):
        self.conn.execute("ROLLBACK")

    # -- meta ---------------------------------------------------------------
    def get_meta(self, key: str, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set_meta(self, key: str, value) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, json.dumps(value)))

    # -- board --------------------------------------------------------------
    def board_entries(self) -> list[dict]:
        rows = self.conn.execute("SELECT entry_json FROM board ORDER BY idx").fetchall()
        return [json.loads(r["entry_json"]) for r in rows]

    def board_head(self) -> tuple[int, str]:
        row = self.conn.execute("SELECT idx, entry_hash FROM board ORDER BY idx DESC LIMIT 1").fetchone()
        if row is None:
            return 0, head_hash([])
        return row["idx"] + 1, row["entry_hash"]

    def append(self, kind: str, payload: dict, timestamp: int) -> dict:
        length, prev = self.board_head()
        entry = make_entry(length, prev, kind, payload, timestamp)
        self.conn.execute("INSERT INTO board(idx, kind, entry_json, entry_hash) VALUES(?,?,?,?)",
                          (entry["index"], kind, json.dumps(entry, sort_keys=True), entry["hash"]))
        return entry

    def entries_of_kind(self, kind: str) -> list[dict]:
        rows = self.conn.execute("SELECT entry_json FROM board WHERE kind=? ORDER BY idx", (kind,)).fetchall()
        return [json.loads(r["entry_json"]) for r in rows]
