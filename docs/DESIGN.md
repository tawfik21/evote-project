# Design notes (material for the technical report)

## 1. Parties and trust

| Party | Holds | Trusted for | NOT trusted for |
|---|---|---|---|
| Election authority | ElGamal secret key `x`, Ed25519 signing key (offline, encrypted) | Running the election honestly up to proofs; not decrypting single ballots | The result (it must prove it) |
| Ballot server | Its Ed25519 key, TLS key, SQLite DB | Availability | Privacy (it never has `x`), integrity (receipts and audit catch it) |
| Voter | Ed25519 key + Schnorr login key (encrypted file) | Their own vote | Ballot validity (they must prove it) |
| Auditor (anyone) | Trust bundle only | n/a | n/a |

## 2. Protocol flow

```
SETUP (authority, offline)
  x <- random,  H = x*G                                    ElGamal election key
  manifest = {id, candidates, H, SchnorrNIZK(x), authority_pk}, Ed25519-signed
  per voter: 80-bit one-time enrolment code; server receives only SHA-256(code)

SERVER INIT
  verify manifest + code list signatures; create board (entry 0 = manifest)
  create server Ed25519 key and ECDSA P-256 TLS certificate; write trust.json

ENROL  (voter -> server, over pinned TLS 1.3)
  voter makes Ed25519 key (sk_v, pk_v) and Schnorr key s, Y = s*G   (saved encrypted)
  sends code + Sign_sk_v{voter_id, pk_v, Y, SchnorrNIZK(s)}         (proof of possession)
  server checks code (constant time, single use) -> appends "voter" entry

LOGIN  (interactive Schnorr identification)
  voter: k random, T = k*G            ------ T ------>
                                      <----- c ------   server: c random, single use, 120 s TTL
  voter: z = k + c*s                  ------ z ------>   server: z*G == T + c*Y ?  -> session token
                                                         (token: 256-bit, stored hashed, 5 min, single use)
VOTE
  for each candidate i:  (A_i, B_i) = (r_i*G, v_i*G + r_i*H),  v_i in {0,1}
      OR-proof_i : "(A_i,B_i) encrypts 0"  OR  "(A_i,B_i) encrypts 1"
  sum-proof      : "sum_i (A_i,B_i) encrypts 1"       (DLEQ with witness sum r_i)
  ballot = Sign_sk_v{election, voter_id, ciphertexts, proofs};  r_i discarded
  server verifies everything, appends "ballot" entry, returns Sign_server{index, entry_hash, tracker}

CLOSE   authority signs {head_hash, ballot_count}; server appends "close"
TALLY   authority audits board, computes (A, B) = sum of ballots per candidate,
        D = x*A,  count = dlog(B - D),  DLEQ proof log_G(H) = log_A(D); signs result
AUDIT   anyone: chain, all signatures, all ZKPs, one ballot per enrolled voter,
        aggregate recomputed, every decryption proof
```

## 3. Algorithms and parameters

| Purpose | Algorithm | Library | Parameters |
|---|---|---|---|
| Group for ElGamal and ZKPs | Edwards25519 prime-order subgroup | libsodium (PyNaCl) | order L ~ 2^252, ~128-bit security |
| Ballot encryption | Exponential ElGamal (additively homomorphic) | libsodium point ops | fresh random r per ciphertext |
| Login | Schnorr identification (interactive Sigma protocol) | libsodium | challenge uniform mod L |
| Ballot validity | Disjunctive Chaum-Pedersen (CDS94) + DLEQ | libsodium | strong Fiat-Shamir, SHA-512 to scalar |
| Correct decryption | Chaum-Pedersen DLEQ | libsodium | strong Fiat-Shamir |
| Signatures | Ed25519 | pyca/cryptography (OpenSSL) | domain-separated canonical JSON |
| Key files | Argon2id + AES-256-GCM | pyca/cryptography | 64 MiB, t=3, p=4; 16 B salt; 12 B nonce; header as AAD |
| Board | SHA-256 hash chain | hashlib | domain-separated |
| Transport | TLS 1.3 only, ECDSA P-256 certificate, pinned | Python ssl (OpenSSL) + pyca x509 | forward secrecy via (EC)DHE |
| Randomness | OS CSPRNG | `secrets`, `os.urandom` | |

**Why two libraries?** pyca/cryptography (OpenSSL) provides the standard primitives (Ed25519, AES-GCM, Argon2id, X.509), but it does not expose raw elliptic-curve point arithmetic. ZKPs and homomorphic ElGamal need exactly that. libsodium does expose it (`crypto_scalarmult_ed25519_noclamp`, `crypto_core_ed25519_add/sub`, `crypto_core_ed25519_is_valid_point`). So every group operation runs in audited constant-time code, and our code only composes the protocol. The earlier modular-arithmetic design (RFC 3526 2048-bit group in pure Python) was about 1000x slower: 17 ms vs 0.016 ms per exponentiation.

## 4. The zero-knowledge proofs

All proofs are Sigma protocols: commit, challenge, response. They have three properties:
- **Completeness:** an honest prover always convinces the verifier.
- **Special soundness:** two accepting transcripts with different challenges reveal the witness, so a cheater cannot answer more than one challenge.
- **Honest-verifier zero-knowledge:** transcripts can be simulated without the witness, so they reveal nothing.

* **Schnorr:** prove knowledge of `s` with `Y = s*G`. Commit `T = k*G`, response `z = k + c*s`, check `z*G = T + c*Y`. The test `test_schnorr_nonce_reuse_would_leak_the_secret` shows why `k` must never be reused.
* **Chaum-Pedersen (DLEQ):** prove the same `w` satisfies `Q1 = w*P1` and `Q2 = w*P2`. "(A, B) encrypts v" is the DLEQ statement `A = r*G`, `B - v*G = r*H`.
* **OR-proof (Cramer, Damgaard, Schoenmakers 1994):** the prover simulates the false branch by choosing its challenge and response first. The hash fixes the sum of the challenges, so at most one branch can be simulated. The verifier cannot tell which branch was real.
* **Fiat-Shamir:** the challenge is a hash of the context (election id, voter id, candidate index), the generators, the statement and the commitments. Omitting the statement ("weak Fiat-Shamir") made Helios proofs forgeable (Bernhard, Pereira, Warinschi 2012). Including the voter id stops a copied ballot from being replayed under another identity (Cortier & Smyth 2013). See `test_copied_ballot_rejected`.
* **Why the login uses an interactive proof and ballots use non-interactive ones:** an interactive Schnorr proof is *deniable*, because the transcript could have been simulated. That makes it good for authentication but useless as evidence. Ballots need to be publicly verifiable and non-repudiable, so they use non-interactive proofs **plus** an Ed25519 signature.

## 5. Key management

| Key | Generated by | Stored | Distributed |
|---|---|---|---|
| ElGamal secret `x` | authority | `authority.key` (Argon2id + AES-GCM, 0600), offline | never; public `H` in manifest with proof of knowledge |
| Authority Ed25519 | authority | `authority.key` | public key in manifest and `trust.json` |
| Enrolment codes | authority | `enrolment_codes.txt` (0600); server stores SHA-256 only | privately to each voter (out of band) |
| Server Ed25519 | server init | `server_signing.key` (encrypted) | public key in `trust.json` |
| TLS key | server init | `tls_key.pem` (PKCS#8, encrypted, 0600) | certificate pinned in `trust.json` |
| Voter Ed25519 + Schnorr | voter client | `<voter>.key` (encrypted) | public keys sent at enrolment, posted on the board |

The trust bundle `trust.json` is the root of trust. Voters must get it through an authentic channel, such as the election website or a printed QR code of its SHA-256.

## 6. Threats and mitigations (each has an automated test)

| Threat | Mitigation | Test / demo |
|---|---|---|
| Eavesdropper reads votes | ElGamal; TLS 1.3 | `test_server_never_sees_plaintext_votes` |
| MITM / fake server | pinned certificate; signed manifest | `fake-cert`, `test_unpinned_certificate_rejected` |
| Environment variables override the pin | `trust_env = False` | `test_environment_ca_bundle_cannot_override_pin` |
| Login replay | single-use challenges, fresh nonce | `replay-login`, `test_login_replay_blocked` |
| Online password guessing | no passwords; lockout after 5 failures | `test_lockout_after_repeated_failures` |
| Stolen key file | Argon2id + AES-GCM; tamper and KDF-downgrade detection | `test_keystore_*` |
| Overvote / negative vote / empty ballot | OR-proofs + sum proof | `overvote`, `test_negative_vote_*`, `test_empty_ballot_*` |
| Double voting | one ballot per voter; single-use session | `double-vote`, `test_ballot_requires_session_*` |
| Ballot copying | proofs bound to voter id; signatures | `copy-ballot` |
| Impersonation | session must match ballot signer | `test_cannot_vote_as_someone_else` |
| Server drops or edits ballots | hash chain, voter signatures, signed receipts | `tamper-db`, `test_database_tampering_*` |
| Authority lies about result | DLEQ decryption proofs, public recount of aggregate | `fake-result`, `test_fake_result_rejected` |
| Small-subgroup / invalid-point input | `is_valid_point` on every received point | `test_point_validation_rejects_bad_points` |
| Unauthorised close | authority signature over the board head | `test_close_requires_authority_signature` |

## 7. Challenges met during implementation (for the report)

1. **Pinning bypass through environment variables.** `requests` lets `REQUESTS_CA_BUNDLE` override `session.verify`. This surfaced during testing because the build machine used an HTTPS proxy. It was fixed with `session.trust_env = False` and a regression test.
2. **The identity point.** libsodium refuses scalar multiplication by 0 and treats the identity as invalid. An election with zero votes produces the identity, so the wrappers handle it explicitly (`test_election_with_no_votes`).
3. **Performance.** The first design used a 2048-bit MODP group in pure Python at 17 ms per exponentiation. Switching to libsodium's curve operations gave 0.016 ms.
4. **Concurrency.** Board appends must be atomic, so they use an in-process lock plus SQLite `BEGIN IMMEDIATE` transactions. That is why the server runs a single process.

## 8. References

- Adida, B. (2008). Helios: Web-based open-audit voting. *USENIX Security Symposium*.
- Bernhard, D., Pereira, O., & Warinschi, B. (2012). How not to prove yourself: Pitfalls of the Fiat-Shamir heuristic and applications to Helios. *ASIACRYPT 2012*.
- Bernstein, D. J., et al. (2012). High-speed high-security signatures (Ed25519). *Journal of Cryptographic Engineering*.
- Biryukov, A., Dinu, D., & Khovratovich, D. (2016). Argon2. RFC 9106.
- Chaum, D., & Pedersen, T. P. (1992). Wallet databases with observers. *CRYPTO '92*.
- Cortier, V., & Smyth, B. (2013). Attacking and fixing Helios: An analysis of ballot secrecy. *Journal of Computer Security*.
- Cramer, R., Damgaard, I., & Schoenmakers, B. (1994). Proofs of partial knowledge and simplified design of witness hiding protocols. *CRYPTO '94*.
- Cramer, R., Gennaro, R., & Schoenmakers, B. (1997). A secure and optimally efficient multi-authority election scheme. *EUROCRYPT '97*.
- ElGamal, T. (1985). A public key cryptosystem and a signature scheme based on discrete logarithms. *IEEE Trans. Inf. Theory*.
- Fiat, A., & Shamir, A. (1986). How to prove yourself. *CRYPTO '86*.
- Rescorla, E. (2018). The Transport Layer Security (TLS) Protocol Version 1.3. RFC 8446.
- Schnorr, C. P. (1991). Efficient signature generation by smart cards. *Journal of Cryptology*.
