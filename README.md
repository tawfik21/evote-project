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

## 3. Run it by hand (for the live presentation)

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

---

## 4. Deploying the server

The server is one process: `evote server run`. It serves HTTPS (TLS 1.3 only) using the certificate made by `evote server init`. **The certificate must list the name or IP address voters will use**, so choose these at `init` time.

### A. Everything on one laptop (simplest; good for the demo)
Use the defaults, as in section 3: `https://localhost:8443`.

### B. Server on one laptop, voters on other laptops (same Wi-Fi / LAN)
On the server laptop, find its LAN IP (`ip addr`, `ipconfig` or `ifconfig`), for example `192.168.1.50`:
```bash
evote server init --data-dir server --package authority/election_package.json \
      --url https://192.168.1.50:8443 --ip 192.168.1.50 --ip 127.0.0.1 --hostname localhost
evote server run --data-dir server --host 0.0.0.0 --port 8443
```
Then:
- Allow TCP port 8443 through the firewall (`sudo ufw allow 8443/tcp` on Ubuntu; on Windows, accept the Defender prompt).
- Copy `server/trust.json` to each voter's laptop (USB stick, email or the group chat; it contains no secrets).
- Voters run the same `evote voter ...` commands with `--trust trust.json`.

> University Wi-Fi often blocks connections between devices. If it does, use a phone hotspot.

### C. Cloud virtual machine (e.g. AWS EC2, Azure or DigitalOcean, Ubuntu 24.04)
1. Create the VM and open inbound **TCP 8443** in its security group or firewall. Note its public IP or DNS name.
2. On the VM:
   ```bash
   sudo apt update && sudo apt install -y python3-venv git
   git clone <your-repo-url> evote && cd evote
   python3 -m venv .venv && source .venv/bin/activate && pip install -e .
   ```
3. Copy **only** `election_package.json` to the VM. **The authority key never goes to the server.**
   ```bash
   scp authority/election_package.json ubuntu@<VM-IP>:evote/
   ```
4. Initialise for the public address, then run:
   ```bash
   evote server init --data-dir server --package election_package.json \
         --url https://<VM-IP>:8443 --ip <VM-IP>          # or --hostname vote.example.com
   evote server run --data-dir server --host 0.0.0.0 --port 8443
   ```
5. To keep it running after you log out, use a systemd service. Create `/etc/systemd/system/evote.service`:
   ```ini
   [Unit]
   Description=evote ballot server
   After=network.target

   [Service]
   User=ubuntu
   WorkingDirectory=/home/ubuntu/evote
   # The server passphrase is supplied via a root-only environment file (chmod 600).
   EnvironmentFile=/etc/evote/passphrase.env
   ExecStart=/home/ubuntu/evote/.venv/bin/evote server run --data-dir server --host 0.0.0.0 --port 8443 --passphrase-env EVOTE_SERVER_PASS
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   ```
   `/etc/evote/passphrase.env` contains `EVOTE_SERVER_PASS=...`. Then:
   ```bash
   sudo systemctl daemon-reload && sudo systemctl enable --now evote
   ```
6. Download `server/trust.json` from the VM and give it to voters.

**Production notes** (worth discussing in the report):
- The built-in server is Werkzeug, which is fine for a prototype. In production, run the app under a WSGI server such as gunicorn. Use **one worker** with several threads, because board appends rely on an in-process lock plus SQLite transactions. Put it behind a reverse proxy or load balancer.
- Use a certificate from a real CA (e.g. Let's Encrypt), and pin its public key in `trust.json`.

---

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

As the MACS902 guidelines require, the use of AI tools must be cited. Parts of this code and documentation were developed with the assistance of Claude (Anthropic). The cryptographic constructions follow the published papers listed in `docs/DESIGN.md`.
