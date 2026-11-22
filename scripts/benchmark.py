"""Micro-benchmarks for the report's performance table.  Run:  python3 scripts/benchmark.py"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evote.core import elgamal, group, keystore, protocol, signing, zkp  # noqa: E402


def timeit(label, fn, n):
    start = time.perf_counter()
    for _ in range(n):
        fn()
    ms = (time.perf_counter() - start) / n * 1000
    print(f"{label:<55} {ms:9.3f} ms")
    return ms


def main():
    akey = signing.generate()
    x, h = elgamal.keygen()
    manifest_env = protocol.create_manifest("bench", ["A", "B", "C"], x, h, akey)
    manifest = manifest_env["body"]
    vkey = signing.generate()
    ballot = protocol.create_ballot(manifest, "v1", 1, vkey)
    vpub = signing.public_hex(vkey)

    print(f"{'operation':<55} {'time':>12}")
    print("-" * 68)
    timeit("scalar multiplication (libsodium)", lambda: group.base_mul(group.random_scalar()), 2000)
    timeit("ElGamal encrypt one value", lambda: elgamal.encrypt(h, 1), 1000)
    timeit("Ed25519 sign (OpenSSL)", lambda: signing.sign(vkey, "b", {"x": 1}), 2000)
    timeit("create ballot, 3 candidates (encrypt + 4 ZKPs + sign)",
           lambda: protocol.create_ballot(manifest, "v1", 1, vkey), 200)
    timeit("verify ballot, 3 candidates (signature + 4 ZKPs)",
           lambda: protocol.verify_ballot(manifest, vpub, ballot), 200)

    s = group.random_scalar()
    y = group.base_mul(s)

    def login():
        p = zkp.SchnorrProver(s)
        c = zkp.new_login_challenge()
        assert zkp.schnorr_login_verify(y, p.commitment, c, p.respond(c))
    timeit("Schnorr login, prover + verifier", login, 1000)

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "k")
        timeit("Argon2id (64 MiB, t=3) + AES-GCM: save key file",
               lambda: keystore.save(path, {"k": "v"}, "benchmark-pass", "b"), 5)
        timeit("Argon2id (64 MiB, t=3) + AES-GCM: load key file",
               lambda: keystore.load(path, "benchmark-pass"), 5)

    for n in (100, 1000):
        ballots = [protocol.verify_ballot(manifest, vpub, ballot)] * n
        start = time.perf_counter()
        protocol.compute_result(manifest, x, ballots, "0" * 64, akey)
        print(f"{'tally ' + str(n) + ' ballots (aggregate + decrypt + proofs)':<55} "
              f"{(time.perf_counter() - start) * 1000:9.1f} ms")

    print("-" * 68)
    print(f"ballot size on the wire: {len(json.dumps(ballot))} bytes (3 candidates)")


if __name__ == "__main__":
    main()
