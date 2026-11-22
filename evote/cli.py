"""Command-line interface:  evote <role> <command> [options]

    evote authority setup  | close | tally
    evote server    init   | run
    evote voter     enrol  | vote  | check
    evote audit
    evote attack    overvote | double-vote | copy-ballot | replay-login | fake-cert | tamper-db | fake-result

Passphrases are prompted for (hidden). For scripted demos only, pass
--passphrase-env NAME to read one from an environment variable instead.
"""

import argparse
import getpass
import json
import os
import ssl
import sys

from evote.clients import api as api_mod
from evote.clients import attacks, auditor, authority, voter
from evote.clients.voter import ClientError
from evote.core import protocol
from evote.core.keystore import KeystoreError
from evote.core.protocol import ValidationError

USE_COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text


def ok(msg: str) -> None:
    print(_c("[ OK ]", "32") + " " + msg)


def bad(msg: str) -> None:
    print(_c("[FAIL]", "31") + " " + msg)


def info(msg: str) -> None:
    print(_c("[ .. ]", "36") + " " + msg)


def get_passphrase(args, prompt: str = "Passphrase: ", confirm: bool = False) -> str:
    if getattr(args, "passphrase_env", None):
        value = os.environ.get(args.passphrase_env)
        if not value:
            raise ClientError(f"environment variable {args.passphrase_env} is not set")
        return value
    first = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise ClientError("passphrases do not match")
    return first


def _transport(args):
    trust = api_mod.load_trust(args.trust)
    return trust, api_mod.HttpsTransport(trust, getattr(args, "server", None))


def print_report(report) -> None:
    for passed, msg in report.checks:
        (ok if passed else bad)(msg)
    if report.result:
        print()
        info("Election result (verified):")
        for name, count in zip(report.result["candidates"], report.result["counts"]):
            print(f"         {name:<20} {count}")
    print()
    (ok if report.ok else bad)("AUDIT PASSED" if report.ok else "AUDIT FAILED")


# ==========================================================================
# authority
# ==========================================================================

def cmd_authority_setup(args):
    candidates = [c.strip() for c in args.candidates.split(",") if c.strip()]
    if args.voters_file:
        with open(args.voters_file) as fh:
            voter_ids = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    else:
        voter_ids = [v.strip() for v in args.voters.split(",") if v.strip()]
    passphrase = get_passphrase(args, "New authority passphrase: ", confirm=True)
    package, codes = authority.setup(args.out, args.title, candidates, voter_ids, passphrase)
    ok(f"election {package['manifest']['body']['election_id']} created: {args.title}")
    ok(f"ElGamal election key generated; Schnorr proof of key ownership attached")
    ok(f"{args.out}/authority.key            (encrypted: Argon2id + AES-256-GCM)  KEEP OFFLINE")
    ok(f"{args.out}/election_package.json    give this to the server operator")
    ok(f"{args.out}/enrolment_codes.txt      give each voter their own code, privately ({len(codes)} voters)")


def cmd_authority_close(args):
    trust, transport = _transport(args)
    resp = authority.close(transport, trust, args.keyfile, get_passphrase(args, "Authority passphrase: "))
    ok(f"election closed (board entry {resp['index']}); no more ballots will be accepted")


def cmd_authority_tally(args):
    trust, transport = _transport(args)
    if getattr(args, "explain", False):
        from evote.clients import explain
        explain.tally(transport, trust, args.keyfile, get_passphrase(args, "Authority passphrase: "))
        return
    body = authority.tally(transport, trust, args.keyfile, get_passphrase(args, "Authority passphrase: "))
    ok("board audited; ballots aggregated homomorphically; only the totals were decrypted")
    ok("result published with a Chaum-Pedersen decryption proof per candidate")
    for name, count in zip(body["candidates"], body["counts"]):
        print(f"         {name:<20} {count}")


# ==========================================================================
# server
# ==========================================================================

def cmd_server_init(args):
    from evote.server.app import initialise

    with open(args.package) as fh:
        package = json.load(fh)
    passphrase = get_passphrase(args, "New server passphrase: ", confirm=True)
    hostnames = args.hostname or ["localhost"]
    ips = args.ip or ["127.0.0.1"]
    trust = initialise(args.data_dir, package, passphrase, args.url, hostnames, ips)
    ok(f"election {trust['election_id']} loaded; manifest signature and code list verified")
    ok(f"server Ed25519 signing key created (encrypted)")
    ok(f"TLS certificate created for {', '.join(hostnames + ips)}  sha256={trust['tls_certificate_sha256'][:32]}...")
    ok(f"{args.data_dir}/trust.json  <- give this to every voter and auditor")


def cmd_server_run(args):
    from evote.server.app import configure_logging, create_app, load_server_key

    passphrase = get_passphrase(args, "Server passphrase: ")
    server_key = load_server_key(args.data_dir, passphrase)
    configure_logging(args.data_dir)
    app = create_app(args.data_dir, server_key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3   # TLS 1.3 only: always (EC)DHE, forward secrecy
    context.load_cert_chain(os.path.join(args.data_dir, "tls_cert.pem"),
                            os.path.join(args.data_dir, "tls_key.pem"), password=passphrase)
    info(f"ballot server on https://{args.host}:{args.port}  (TLS 1.3 only)  Ctrl-C to stop")
    app.run(host=args.host, port=args.port, ssl_context=context, threaded=True)


# ==========================================================================
# voter
# ==========================================================================

def cmd_voter_enrol(args):
    trust, transport = _transport(args)
    passphrase = get_passphrase(args, "Choose a passphrase for your key file: ", confirm=True)
    resp = voter.enrol(transport, trust, args.voter_id, args.code, args.keyfile, passphrase)
    ok(f"enrolled as {args.voter_id} (board entry {resp['index']})")
    ok(f"your keys are in {args.keyfile} (encrypted); only your PUBLIC keys were sent")


def cmd_voter_vote(args):
    trust, transport = _transport(args)
    keys = voter.load_keys(args.keyfile, get_passphrase(args, "Key file passphrase: "))
    if args.explain:
        from evote.clients import explain
        receipt, _ = explain.vote(transport, trust, keys, args.choice)
        print()
    else:
        info("logging in with a Schnorr zero-knowledge proof (your secret key is never sent)")
        receipt, _ = voter.vote(transport, trust, keys, args.choice)
    out = args.receipt_out or f"receipt-{keys.voter_id}.json"
    with open(out, "w") as fh:
        json.dump(receipt, fh, indent=2)
    body = receipt["body"]
    ok("ballot encrypted (ElGamal) with a 0-or-1 proof per candidate and an exactly-one-vote proof")
    ok(f"ballot accepted at board entry {body['index']}; server-signed receipt verified")
    ok(f"tracking code: {body['tracker'][:16]}   receipt saved to {out}")


def cmd_voter_check(args):
    trust, transport = _transport(args)
    with open(args.receipt) as fh:
        receipt = json.load(fh)
    results = voter.check_receipt(transport, trust, receipt)
    for passed, msg in results:
        (ok if passed else bad)(msg)
    if not all(p for p, _ in results):
        sys.exit(1)


# ==========================================================================
# audit
# ==========================================================================

def cmd_audit(args):
    trust = api_mod.load_trust(args.trust)
    if args.board_file:
        data = auditor.load_board(args.board_file)
        info(f"auditing offline copy {args.board_file}")
    else:
        transport = api_mod.HttpsTransport(trust, args.server)
        data = auditor.fetch_board(transport)
        info(f"downloaded {len(data['entries'])} board entries from {transport.base}")
    if args.save:
        auditor.save_board(data, args.save)
        info(f"board saved to {args.save}")
    report = auditor.audit(trust, data)
    print_report(report)
    if not report.ok:
        sys.exit(1)


# ==========================================================================
# attacks
# ==========================================================================

def _show(blocked: bool, msg: str):
    (ok if blocked else bad)(("ATTACK BLOCKED: " if blocked else "ATTACK SUCCEEDED: ") + msg)
    if not blocked:
        sys.exit(1)


def cmd_attack(args):
    name = args.attack
    if name == "tamper-db":
        done, msg = attacks.tamper_database(args.db)
        (info if done else bad)(msg)
        return
    trust, transport = _transport(args)
    if name == "fake-cert":
        return _show(*attacks.fake_certificate(trust))
    if name == "fake-result":
        secret, akey, _ = authority.load_keys(args.keyfile, get_passphrase(args, "Authority passphrase: "))
        return _show(*attacks.fake_result(transport.get("/api/board")["entries"], trust, secret, akey))
    keys = voter.load_keys(args.keyfile, get_passphrase(args, "Key file passphrase: "))
    if name == "overvote":
        return _show(*attacks.overvote(transport, trust, keys, args.weight))
    if name == "double-vote":
        return _show(*attacks.double_vote(transport, trust, keys, args.choice))
    if name == "copy-ballot":
        return _show(*attacks.copy_ballot(transport, trust, keys))
    if name == "replay-login":
        return _show(*attacks.replay_login(transport, keys))


# ==========================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evote", description="Verifiable e-voting prototype with zero-knowledge proofs")
    roles = p.add_subparsers(dest="role", required=True)

    def pw(sp):
        sp.add_argument("--passphrase-env", metavar="VAR", help="read passphrase from env var (demos only)")

    def net(sp):
        sp.add_argument("--trust", required=True, help="trust bundle (trust.json) from the server operator")
        sp.add_argument("--server", help="override the server URL in the trust bundle")

    # authority
    a = roles.add_parser("authority", help="election authority").add_subparsers(dest="cmd", required=True)
    s = a.add_parser("setup", help="create election keys, manifest and enrolment codes")
    s.add_argument("--out", required=True)
    s.add_argument("--title", required=True)
    s.add_argument("--candidates", required=True, help="comma-separated names")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--voters", help="comma-separated voter ids")
    g.add_argument("--voters-file", help="file with one voter id per line")
    pw(s)
    s.set_defaults(func=cmd_authority_setup)
    for name, fn in (("close", cmd_authority_close), ("tally", cmd_authority_tally)):
        s = a.add_parser(name)
        net(s)
        s.add_argument("--keyfile", required=True)
        if name == "tally":
            s.add_argument("--explain", action="store_true", help="show every cryptographic step")
        pw(s)
        s.set_defaults(func=fn)

    # server
    sv = roles.add_parser("server", help="ballot server").add_subparsers(dest="cmd", required=True)
    s = sv.add_parser("init", help="load an election package and create server keys + trust bundle")
    s.add_argument("--data-dir", required=True)
    s.add_argument("--package", required=True)
    s.add_argument("--url", default="https://localhost:8443", help="URL voters will use")
    s.add_argument("--hostname", action="append", help="DNS name for the certificate (repeatable)")
    s.add_argument("--ip", action="append", help="IP address for the certificate (repeatable)")
    pw(s)
    s.set_defaults(func=cmd_server_init)
    s = sv.add_parser("run", help="start the HTTPS server")
    s.add_argument("--data-dir", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    pw(s)
    s.set_defaults(func=cmd_server_run)

    # voter
    v = roles.add_parser("voter", help="voter").add_subparsers(dest="cmd", required=True)
    s = v.add_parser("enrol")
    net(s)
    s.add_argument("--voter-id", required=True)
    s.add_argument("--code", required=True)
    s.add_argument("--keyfile", required=True)
    pw(s)
    s.set_defaults(func=cmd_voter_enrol)
    s = v.add_parser("vote")
    net(s)
    s.add_argument("--keyfile", required=True)
    s.add_argument("--choice", required=True, help="candidate name or number")
    s.add_argument("--receipt-out")
    s.add_argument("--explain", action="store_true", help="show every cryptographic step")
    pw(s)
    s.set_defaults(func=cmd_voter_vote)
    s = v.add_parser("check", help="check your receipt against the public board")
    net(s)
    s.add_argument("--receipt", required=True)
    s.set_defaults(func=cmd_voter_check)

    # audit
    s = roles.add_parser("audit", help="verify the whole election (anyone)")
    s.add_argument("--trust", required=True)
    s.add_argument("--server")
    s.add_argument("--board-file", help="audit a saved copy instead of downloading")
    s.add_argument("--save", help="save the downloaded board to a file")
    s.set_defaults(func=cmd_audit)

    # attacks
    s = roles.add_parser("attack", help="attack simulations for the demo")
    s.add_argument("attack", choices=["overvote", "double-vote", "copy-ballot", "replay-login",
                                      "fake-cert", "tamper-db", "fake-result"])
    s.add_argument("--trust")
    s.add_argument("--server")
    s.add_argument("--keyfile", help="voter key (or authority key for fake-result)")
    s.add_argument("--choice", default="1")
    s.add_argument("--weight", type=int, default=5)
    s.add_argument("--db", help="server.db path (tamper-db)")
    pw(s)
    s.set_defaults(func=cmd_attack)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (ClientError, KeystoreError, ValidationError, api_mod.ServerError) as exc:
        bad(str(exc))
        sys.exit(1)
    except api_mod.tls_error_types() as exc:
        bad(f"TLS error - the server's certificate is not the pinned one, or it is unreachable: {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
