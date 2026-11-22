"""Flask ballot server.

The server is deliberately *untrusted* for vote privacy: it never holds the
election decryption key and never sees a plaintext vote. It is trusted only
to be available; anything else it does wrong (dropping, altering or
reordering ballots) is caught by receipts and by the public audit.

Endpoints (all JSON):
    GET  /api/election         signed manifest + current state
    POST /api/enrol            one-time code + voter public keys (+ proofs)
    POST /api/login/commit     Schnorr step 1: commitment T      -> challenge c
    POST /api/login/respond    Schnorr step 3: response z        -> session token
    POST /api/ballot           signed ballot (Bearer token)      -> signed receipt
    GET  /api/board            all board entries + signed head
    POST /api/close            authority-signed close request
    POST /api/result           authority-signed result with decryption proofs
    GET  /                     human-readable view of the board
"""

import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import threading
import time

from flask import Flask, jsonify, request

from evote.core import group, protocol, signing, zkp
from evote.core.audit import audit_board
from evote.core.keystore import load as load_keystore
from evote.core.protocol import ValidationError
from evote.server.db import Database

CHALLENGE_TTL = 120          # seconds a login challenge stays valid
SESSION_TTL = 300            # seconds a session token stays valid
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
MAX_BODY_BYTES = 256 * 1024


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ServerState:
    def __init__(self, data_dir: str, server_key):
        self.data_dir = data_dir
        self.db = Database(os.path.join(data_dir, "server.db"))
        self.server_key = server_key
        self.lock = threading.Lock()
        entries = self.db.entries_of_kind("election")
        if not entries:
            raise RuntimeError("server database is not initialised; run 'evote server init' first")
        self.manifest_envelope = entries[0]["payload"]
        self.manifest = self.manifest_envelope["body"]
        self.election_id = self.manifest["election_id"]
        self.log = logging.getLogger("evote.server")

    @property
    def state(self) -> str:
        return self.db.get_meta("state", "open")

    def signed_head(self) -> dict:
        length, head = self.db.board_head()
        return protocol.create_head(self.server_key, self.election_id, length, head)


def _json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "request body must be a JSON object")
    return data


def _field(data: dict, name: str, max_len: int = 4096) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ApiError(400, f"field '{name}' missing or invalid")
    return value


def create_app(data_dir: str, server_key) -> Flask:
    app = Flask("evote-server")
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    st = ServerState(data_dir, server_key)
    app.config["EVOTE"] = st

    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError):
        return jsonify({"error": exc.message}), exc.status

    @app.errorhandler(413)
    def _too_large(_exc):
        return jsonify({"error": "request too large"}), 413

    @app.after_request
    def _security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    # ------------------------------------------------------------------ read
    @app.get("/api/election")
    def election():
        return jsonify({"manifest": st.manifest_envelope, "state": st.state})

    @app.get("/api/board")
    def board():
        with st.lock:
            return jsonify({"entries": st.db.board_entries(), "head": st.signed_head()})

    # ----------------------------------------------------------------- enrol
    @app.post("/api/enrol")
    def enrol():
        data = _json_body()
        code = _field(data, "code", 64)
        envelope = data.get("enrolment")
        with st.lock:
            if st.state != "open":
                raise ApiError(409, "election is not open")
            try:
                body = protocol.verify_enrolment(envelope, st.election_id)
            except ValidationError as exc:
                st.log.warning("enrolment rejected: %s", exc)
                raise ApiError(400, f"enrolment rejected: {exc}")
            voter_id = body["voter_id"]
            row = st.db.conn.execute("SELECT code_hash, used FROM enrolment_codes WHERE voter_id=?",
                                     (voter_id,)).fetchone()
            expected = row["code_hash"] if row else _sha256("no such voter")
            supplied = protocol.enrolment_code_hash(st.election_id, voter_id, code)
            # Constant-time comparison, and the same error for "unknown voter" and "wrong code".
            if not hmac.compare_digest(expected, supplied) or row is None:
                st.log.warning("enrolment rejected for %s: bad code", voter_id)
                raise ApiError(403, "invalid voter id or enrolment code")
            if row["used"]:
                raise ApiError(409, "this enrolment code has already been used")
            st.db.begin()
            try:
                entry = st.db.append("voter", envelope, protocol.now())
                st.db.conn.execute("UPDATE enrolment_codes SET used=1 WHERE voter_id=?", (voter_id,))
                st.db.conn.execute("INSERT INTO voters(voter_id, sign_public_key, login_public_key) VALUES(?,?,?)",
                                   (voter_id, body["sign_public_key"], body["login_public_key"]))
                st.db.commit()
            except Exception:
                st.db.rollback()
                raise
            st.log.info("voter %s enrolled at board index %d", voter_id, entry["index"])
            return jsonify({"status": "enrolled", "index": entry["index"], "entry_hash": entry["hash"]})

    # ----------------------------------------------------------------- login
    @app.post("/api/login/commit")
    def login_commit():
        data = _json_body()
        voter_id = _field(data, "voter_id", 64)
        try:
            commitment = group.point_from_hex(data.get("commitment"))
        except group.GroupError as exc:
            raise ApiError(400, f"invalid commitment: {exc}")
        with st.lock:
            voter = st.db.conn.execute("SELECT locked_until FROM voters WHERE voter_id=?", (voter_id,)).fetchone()
            if voter is None:
                raise ApiError(403, "login failed")
            if voter["locked_until"] > time.time():
                raise ApiError(429, "too many failed logins; try again later")
            challenge = zkp.new_login_challenge()
            challenge_id = secrets.token_hex(16)
            st.db.conn.execute(
                "INSERT INTO challenges(challenge_id, voter_id, commitment, challenge, expires) VALUES(?,?,?,?,?)",
                (challenge_id, voter_id, commitment.hex(), group.scalar_to_hex(challenge),
                 int(time.time()) + CHALLENGE_TTL))
        return jsonify({"challenge_id": challenge_id, "challenge": group.scalar_to_hex(challenge)})

    @app.post("/api/login/respond")
    def login_respond():
        data = _json_body()
        challenge_id = _field(data, "challenge_id", 64)
        try:
            response = group.scalar_from_hex(data.get("response"))
        except group.GroupError as exc:
            raise ApiError(400, f"invalid response: {exc}")
        with st.lock:
            row = st.db.conn.execute("SELECT * FROM challenges WHERE challenge_id=?", (challenge_id,)).fetchone()
            if row is None or row["used"] or row["expires"] < time.time():
                st.log.warning("login rejected: unknown, expired or replayed challenge")
                raise ApiError(403, "login failed: challenge unknown, expired or already used")
            # Burn the challenge before checking, so each challenge gets exactly one attempt.
            st.db.conn.execute("UPDATE challenges SET used=1 WHERE challenge_id=?", (challenge_id,))
            voter = st.db.conn.execute("SELECT * FROM voters WHERE voter_id=?", (row["voter_id"],)).fetchone()
            ok = zkp.schnorr_login_verify(bytes.fromhex(voter["login_public_key"]), bytes.fromhex(row["commitment"]),
                                          group.scalar_from_hex(row["challenge"]), response)
            if not ok:
                failures = voter["failed_logins"] + 1
                locked = int(time.time()) + LOCKOUT_SECONDS if failures >= MAX_FAILED_LOGINS else 0
                st.db.conn.execute("UPDATE voters SET failed_logins=?, locked_until=? WHERE voter_id=?",
                                   (0 if locked else failures, locked, voter["voter_id"]))
                st.log.warning("login failed for %s (Schnorr proof invalid)", voter["voter_id"])
                raise ApiError(403, "login failed")
            token = secrets.token_urlsafe(32)
            st.db.conn.execute("UPDATE voters SET failed_logins=0 WHERE voter_id=?", (voter["voter_id"],))
            st.db.conn.execute("INSERT INTO sessions(token_hash, voter_id, expires) VALUES(?,?,?)",
                               (_sha256(token), voter["voter_id"], int(time.time()) + SESSION_TTL))
            st.log.info("voter %s logged in (Schnorr ZKP accepted)", voter["voter_id"])
        return jsonify({"session_token": token, "expires_in": SESSION_TTL})

    # ---------------------------------------------------------------- ballot
    @app.post("/api/ballot")
    def cast_ballot():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise ApiError(401, "missing session token")
        token_hash = _sha256(auth[len("Bearer "):].strip())
        envelope = _json_body().get("ballot")
        with st.lock:
            session = st.db.conn.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
            if session is None or session["used"] or session["expires"] < time.time():
                raise ApiError(401, "session token invalid, expired or already used")
            # One ballot attempt per login.
            st.db.conn.execute("UPDATE sessions SET used=1 WHERE token_hash=?", (token_hash,))
            voter_id = session["voter_id"]
            if st.state != "open":
                raise ApiError(409, "election is not open")
            voter = st.db.conn.execute("SELECT * FROM voters WHERE voter_id=?", (voter_id,)).fetchone()
            if voter["has_voted"]:
                st.log.warning("ballot rejected for %s: already voted", voter_id)
                raise ApiError(409, "this voter has already voted")
            body = envelope.get("body") if isinstance(envelope, dict) else None
            if not isinstance(body, dict) or body.get("voter_id") != voter_id:
                raise ApiError(403, "ballot voter id does not match the logged-in voter")
            try:
                protocol.verify_ballot(st.manifest, voter["sign_public_key"], envelope)
            except ValidationError as exc:
                st.log.warning("ballot rejected for %s: %s", voter_id, exc)
                raise ApiError(400, f"ballot rejected: {exc}")
            st.db.begin()
            try:
                entry = st.db.append("ballot", envelope, protocol.now())
                st.db.conn.execute("UPDATE voters SET has_voted=1 WHERE voter_id=?", (voter_id,))
                st.db.commit()
            except Exception:
                st.db.rollback()
                raise
            tracker = protocol.ballot_tracker(envelope)
            receipt = protocol.create_receipt(st.server_key, st.election_id, voter_id, entry, tracker)
            st.log.info("ballot accepted from %s at board index %d", voter_id, entry["index"])
        return jsonify({"receipt": receipt})

    # ------------------------------------------------------- authority calls
    @app.post("/api/close")
    def close():
        envelope = _json_body().get("close")
        with st.lock:
            if st.state != "open":
                raise ApiError(409, "election is not open")
            try:
                body = protocol.verify_close(envelope, st.manifest)
            except ValidationError as exc:
                st.log.warning("close rejected: %s", exc)
                raise ApiError(403, f"close rejected: {exc}")
            length, head = st.db.board_head()
            ballots = len(st.db.entries_of_kind("ballot"))
            if body["head_hash"] != head or body.get("ballot_count") != ballots:
                raise ApiError(409, "board has changed since the authority fetched it; fetch again and retry")
            st.db.begin()
            try:
                entry = st.db.append("close", envelope, protocol.now())
                st.db.set_meta("state", "closed")
                st.db.commit()
            except Exception:
                st.db.rollback()
                raise
            st.log.info("election closed by authority with %d ballots", ballots)
        return jsonify({"status": "closed", "index": entry["index"], "entry_hash": entry["hash"]})

    @app.post("/api/result")
    def result():
        envelope = _json_body().get("result")
        with st.lock:
            if st.state != "closed":
                raise ApiError(409, "election must be closed (and not yet tallied)")
            entries = st.db.board_entries()
            report = audit_board(entries, st.manifest["authority_public_key"], st.election_id)
            if not report.ok:
                raise ApiError(500, "board failed self-audit; refusing to publish a result")
            try:
                protocol.verify_result(envelope, st.manifest, report.ballot_ciphertexts(), entries[-1]["hash"])
            except ValidationError as exc:
                st.log.warning("result rejected: %s", exc)
                raise ApiError(400, f"result rejected: {exc}")
            st.db.begin()
            try:
                entry = st.db.append("result", envelope, protocol.now())
                st.db.set_meta("state", "tallied")
                st.db.commit()
            except Exception:
                st.db.rollback()
                raise
            st.log.info("result published: %s", envelope["body"]["counts"])
        return jsonify({"status": "published", "index": entry["index"]})

    # ------------------------------------------------------------ html view
    @app.get("/")
    def index():
        entries = st.db.board_entries()
        rows = []
        for e in entries:
            detail = ""
            if e["kind"] == "voter":
                detail = "voter " + html.escape(e["payload"]["body"]["voter_id"])
            elif e["kind"] == "ballot":
                detail = ("voter " + html.escape(e["payload"]["body"]["voter_id"]) + " &middot; tracker "
                          + protocol.ballot_tracker(e["payload"])[:16])
            elif e["kind"] == "result":
                body = e["payload"]["body"]
                detail = ", ".join(f"{html.escape(c)}: {n}" for c, n in zip(body["candidates"], body["counts"]))
            rows.append(f"<tr><td>{e['index']}</td><td>{e['kind']}</td><td><code>{e['hash'][:16]}</code></td>"
                        f"<td>{detail}</td></tr>")
        page = f"""<!doctype html><html><head><meta charset="utf-8"><title>evote bulletin board</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left}}
code{{font-size:12px}}</style></head><body>
<h1>{html.escape(st.manifest['title'])}</h1>
<p>Election <code>{st.election_id}</code> &middot; state <b>{st.state}</b> &middot; candidates:
{html.escape(', '.join(st.manifest['candidates']))}</p>
<p>Public bulletin board ({len(entries)} entries). Verify it yourself with <code>evote audit</code>.</p>
<table><tr><th>#</th><th>kind</th><th>hash</th><th>details</th></tr>{''.join(rows)}</table></body></html>"""
        return page, 200, {"Content-Type": "text/html; charset=utf-8",
                           "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}

    return app


# ==========================================================================
# Server initialisation (run once, offline)
# ==========================================================================

def initialise(data_dir: str, election_package: dict, passphrase: str, server_url: str,
               hostnames: list[str], ip_addresses: list[str], kdf_params: dict | None = None) -> dict:
    """Create the database, the server keys and the voters' trust bundle."""
    from evote.core import keystore, tls

    os.makedirs(data_dir, exist_ok=True)
    os.chmod(data_dir, 0o700)
    db_path = os.path.join(data_dir, "server.db")
    if os.path.exists(db_path):
        raise RuntimeError(f"{db_path} already exists; refusing to overwrite an election")

    manifest = protocol.verify_manifest(election_package["manifest"])
    codes_env = election_package["enrolment_codes"]
    if not signing.verify_signed(manifest["authority_public_key"], "enrolment-codes", codes_env) \
            or codes_env["body"].get("election_id") != manifest["election_id"]:
        raise ValidationError("enrolment code list is not signed by the election authority")

    db = Database(db_path)
    db.begin()
    db.append("election", election_package["manifest"], protocol.now())
    for voter_id, code_hash in codes_env["body"]["code_hashes"].items():
        db.conn.execute("INSERT INTO enrolment_codes(voter_id, code_hash) VALUES(?,?)", (voter_id, code_hash))
    db.set_meta("state", "open")
    db.commit()

    server_key = signing.generate()
    keystore.save(os.path.join(data_dir, "server_signing.key"),
                  {"ed25519": signing.private_to_hex(server_key)}, passphrase, "server-signing", kdf_params)
    pem = tls.generate_certificate(os.path.join(data_dir, "tls_cert.pem"), os.path.join(data_dir, "tls_key.pem"),
                                   passphrase, hostnames, ip_addresses)
    trust = {
        "election_id": manifest["election_id"],
        "title": manifest["title"],
        "server_url": server_url,
        "server_public_key": signing.public_hex(server_key),
        "authority_public_key": manifest["authority_public_key"],
        "tls_certificate_pem": pem,
        "tls_certificate_sha256": tls.fingerprint(pem),
    }
    with open(os.path.join(data_dir, "trust.json"), "w") as fh:
        json.dump(trust, fh, indent=2)
    return trust


def load_server_key(data_dir: str, passphrase: str):
    secrets_dict = load_keystore(os.path.join(data_dir, "server_signing.key"), passphrase)
    return signing.private_from_hex(secrets_dict["ed25519"])


def configure_logging(data_dir: str) -> None:
    """High-level events only. Keys, codes, tokens and ballots are never logged."""
    handler = logging.FileHandler(os.path.join(data_dir, "server.log"))
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger = logging.getLogger("evote.server")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.addHandler(logging.StreamHandler())
