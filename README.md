# evote: Secure E-Voting Prototype with Verifiable Ballots

MACS902 Modern Cryptography group project.

Voters log in with a **Schnorr zero-knowledge proof**. Their ballots are **ElGamal-encrypted** and carry **zero-knowledge proofs** that each ballot is valid (one vote, for one candidate). Ballots are posted on a **hash-chained public bulletin board**. The tally is computed **homomorphically**, so individual ballots are never decrypted, and the result comes with a **proof of correct decryption**. Anyone can audit the whole election.

| Property | How it is achieved |
|---|---|
| Confidentiality | Exponential ElGamal on Edwards25519 (libsodium); only the aggregate is decrypted; TLS 1.3 in transit |
| Integrity | SHA-256 hash-chained board, Ed25519 signatures, AES-GCM on key files |
| Authentication | Interactive Schnorr ZKP login, one-time enrolment codes, pinned TLS certificate |
| Non-repudiation | Voters sign ballots (Ed25519); the server signs receipts and the board head; the authority signs manifest, close and result |
| Ballot validity | Disjunctive Chaum-Pedersen proofs (each entry is 0 or 1) plus a DLEQ proof (exactly one vote) |
| Verifiable tally | Chaum-Pedersen proof that each published count is the true decryption of the aggregate |

See [`docs/DESIGN.md`](docs/DESIGN.md) for the cryptography, key management and threat model.

---

## 1. Install

Requires Python 3.10 or later. Works on Linux, macOS and Windows (use WSL for `demo.sh`).

```bash
git clone <your-repo-url> evote && cd evote
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
evote --help
```

## 2. Run the full demo (one command)

```bash
./scripts/demo.sh
```

This runs the authority, starts the HTTPS server, enrols 4 voters, casts 3 honest ballots and runs 7 attacks. It then closes the election, tallies it and audits everything. The demo files go in `demo_run/`.

## 3. Run it by hand 

Open four terminals in the project folder (with the venv activated). Every passphrase is **prompted for and hidden**.

**Terminal 1: authority (offline machine in real life)**
```bash
evote authority setup --out authority --title "Student Council 2026" \
      --candidates "Alice,Bob,Carol" --voters "v1,v2,v3"
cat authority/enrolment_codes.txt      # give each voter only their own code
```

**Terminal 2: server operator**
```bash
evote server init --data-dir server --package authority/election_package.json
evote server run  --data-dir server          # https://localhost:8443, TLS 1.3 only
```
`server/trust.json` is the **trust bundle**. Give a copy to every voter and auditor. It contains the pinned TLS certificate and the server's and authority's public keys.

**Terminal 3: voters**
```bash
evote voter enrol --trust server/trust.json --voter-id v1 --code <v1's code> --keyfile v1.key
evote voter vote  --trust server/trust.json --keyfile v1.key --choice Alice
evote voter check --trust server/trust.json --receipt receipt-v1.json
```

**Terminal 4: attacks, then close / tally / audit**
```bash
evote attack overvote     --trust server/trust.json --keyfile v2.key   # ZKP rejects 5 votes
evote attack replay-login --trust server/trust.json --keyfile v2.key
evote attack fake-cert    --trust server/trust.json

evote authority close --trust server/trust.json --keyfile authority/authority.key
evote authority tally --trust server/trust.json --keyfile authority/authority.key
evote audit           --trust server/trust.json

evote attack tamper-db --db server/server.db     # insider rewrites a ballot
evote audit            --trust server/trust.json # detects it
```

Open `https://localhost:8443/` in a browser to see the public board. The browser will warn that the certificate is self-signed; that is expected, because only the CLI pins it.


## 5. Tests and checks

```bash
pytest -q                     # 53 tests: crypto units, full elections, every attack, live TLS
bandit -r evote               # static security analysis (0 issues)
pip-audit                     # known-vulnerability scan of dependencies
python3 scripts/benchmark.py  # performance table for the report
```

## 6. Project layout

```
evote/
  core/                 shared by server, clients and auditor
    group.py            Edwards25519 prime-order group (libsodium) + Fiat-Shamir hashing
    elgamal.py          exponential ElGamal (homomorphic)
    zkp.py              Schnorr (interactive + NIZK), Chaum-Pedersen, disjunctive OR-proofs
    protocol.py         build/verify manifest, enrolment, ballot, receipt, close, result
    audit.py            full independent verification of a board
    board.py            hash-chained bulletin board
    signing.py          Ed25519 (pyca/cryptography, OpenSSL)
    keystore.py         Argon2id + AES-256-GCM key files (chmod 600)
    tls.py              self-signed ECDSA P-256 certificate
  server/app.py, db.py  Flask HTTPS API + SQLite
  clients/              voter, authority, auditor, attacks, HTTPS transport with pinning
  cli.py                `evote` command
tests/                  pytest suite
scripts/                demo.sh, benchmark.py
docs/DESIGN.md          design notes for the technical report
```

## 7. Known limitations

- A single authority holds the decryption key. Threshold decryption would split it across several trustees.
- There is no coercion resistance. A voter can be watched while voting. The client does discard the ElGamal randomness, so the voter cannot prove their vote afterwards.
- Voter identities are public on the board (ballots are encrypted, but who voted is visible), as in Helios.
- The interactive Schnorr login is honest-verifier zero-knowledge. That is fine here because the server picks a uniformly random challenge.
- Python cannot reliably wipe secrets from memory.

## Academic integrity

As the MACS902 guidelines require, the use of AI tools must be cited. Parts of this code and documentation were developed with the assistance of Claude (Anthropic)
