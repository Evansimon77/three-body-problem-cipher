# Threat model & bit-security claim

**Status: UNVETTED research cipher.** This document states what the design *intends* to
resist and the *honest* security numbers we have measured or derived. None of it is a proof.
The only thing that turns "I think it's secure" into "it's secure" is Phase 7 (outside
experts failing to break it). Until then this is a learning artifact and is never used to
protect real data.

---

## 1. What we are protecting, and from whom

**Asset:** the confidentiality and integrity of messages encrypted with the shipped stack
(the 4-map XOR combiner under the auto-rekey ratchet, wrapped by an AEAD shell).

**The attacker can:**
- See *all* ciphertext (it travels over an open channel).
- See the public nonce / SIV that ships with each message.
- Know the entire algorithm and every constant (Kerckhoffs's principle — no security by obscurity).
- Run chosen-plaintext / chosen-ciphertext queries (we assume the strong setting).
- Capture the *live* key state at one moment in time (memory-disclosure / device seizure).

**The attacker does NOT have:**
- The master key (a 256-bit secret) or any past chain key the ratchet has already burned.
- The ability to run more than ~2^128 operations (the conventional "computationally infeasible"
  line; a 256-bit key sits comfortably above it).

**Explicitly OUT of scope** (handled elsewhere or not claimed): side channels other than the
timing leak tracked in [CONSTANT_TIME.md](CONSTANT_TIME.md); fault injection; protecting the
key while it is in use; and — most importantly — being the *only* lock. The deployment
(Phase 6, "Option B") puts this cipher as the OUTER wall over a vetted inner vault (AES-256-GCM
or ChaCha20-Poly1305), so if the chaos wall ever cracks the data is still fully protected. This
is now BUILT, not just intended — see `twolock.py` and the threat row below.

---

## 2. The threats and how the design answers each

| Threat | Answer in the design | Where |
|---|---|---|
| **Keystream reuse** (two-time pad) | Fresh random nonce per message (AEAD), or a synthetic IV derived from the message itself (SIV) — two different messages can never share a keystream. | `aead.py`, `siv.py` |
| **Tampering / forgery** | Encrypt-then-MAC (HMAC-SHA256), verified in constant time before decrypting. | `aead.py` |
| **Wrong-key / garbage** | Same MAC check — fails closed, never returns plaintext. | `aead.py` |
| **Key-confusion** (one blob opens under two keys) | A key-commitment (#6) binds each blob to exactly one key: `C = HMAC(HMAC(key,"commit-key"), salt‖aad)`, verified in constant time. A cross-key forgery needs an HMAC-SHA256 collision (~2^128). Closes the gap that breaks AES-GCM / ChaCha20-Poly1305. | `commit.py`, `aead.py`, `siv.py` |
| **Stream manipulation** (reorder / drop / duplicate / truncate chunks) | Streaming AEAD binds each chunk's index and a `final` flag into its HMAC tag, so a reordered/dropped/duplicated chunk fails to verify and a truncated stream never delivers the authenticated final marker. | `streaming.py` |
| **Weak keys** | All key material passes a SHA-512 KDF; the weak-parameter band of `p` is rejected and remapped. A caller cannot pick a bad key. | `engine.from_master`, `engine.__init__` |
| **State roll-back / invertibility** | The raw linear state is never emitted: a nonlinear ARX finalizer + truncation (4 of 8 bytes) + the 4-map XOR hide each map's footprint. | `engine._finalize`, `multimap.py` |
| **Past-message recovery after a key leak** | Forward secrecy: a one-way HMAC chain burns each key after use, so a live capture can't decrypt earlier traffic. Available as a keystream (per-epoch) and now wired into the shell as a per-message **session AEAD** (item A). | `ratchet.py`, `ratchet_aead.py` |
| **Period repetition** | Each 64 KiB epoch is a fresh ~2^247 orbit; re-keying dissolves the period limit, so usable length is effectively unbounded. | `ratchet.py` |
| **Man-in-the-middle on key agreement** | Triple-DH (static + ephemeral) authenticated exchange; a MITM lacking a party's static private key cannot derive the session key. | `auth_keyexchange.py` |
| **Quantum / harvest-now-decrypt-later** (record DH today, break it with a future quantum computer) | Hybrid key agreement (item F): mix the classical DH secret with a vetted **ML-KEM-768** (FIPS 203) secret; the session key survives if EITHER primitive holds. Defeats passive harvest-now-decrypt-later. (Unauthenticated on its own — use the authenticated PQ handshake below when an active MITM is in scope.) | `pq_keyexchange.py` |
| **Active MITM that also survives quantum** (impersonation, now or post-quantum) | Authenticated PQ handshake: confidentiality is hybrid DH + ML-KEM-768, and authentication is ALSO hybrid — the triple-DH **static binding** AND a vetted **ML-DSA-65** (FIPS 204) signature over the full transcript. An impostor must defeat BOTH to impersonate: granted a total break of one, the other still rejects her (measured in `attacks/auth_pq_attack.py`, 6/6: quantum-broke-DH → ML-DSA still rejects; ML-DSA-broke → static binding still locks her out). Closes the "unauthenticated" caveat on the row above. | `auth_pq_keyexchange.py` |
| **Timing side channel** | Both channels closed: the secret-dependent *branch* (mask-select, 1.0% spread) and the secret-dependent *divide* (Rust precomputed-reciprocal multiply-shift — measured 0.41% spread across 128 secret keys, no hardware divide on the secret in the hot loop). | [CONSTANT_TIME.md](CONSTANT_TIME.md), `rust/src/lib.rs` |
| **The chaos cipher being broken at all** (the unvetted keystream fails) | **Two locks ("Option B"):** the chaos AEAD is only ever the OUTER wall over a vetted inner vault (AES-256-GCM / ChaCha20-Poly1305), with independent HKDF-derived keys. Even granting the attacker a *total* chaos break (the outer key), peeling the wall leaves AES-256-GCM (~2^128) — the plaintext stays protected and the inner vault independently catches any forgery. Confidentiality + integrity rest on the vetted lock; chaos is a sacrificial extra barrier. Measured in `attacks/twolock_attack.py` (5/5). | `twolock.py` |

---

## 3. Bit-security claim (honest)

A "bit-security" number `b` means the best known attack costs about 2^b operations. We report
the *smallest* of the credible attack costs — the real strength is the weakest link, not the
biggest number we can quote.

| Attack path | Cost | Source |
|---|---|---|
| Brute-force the 256-bit master key | 2^256 | key size |
| Meet-in-the-middle on the combined 4-map state (balanced split) | ~2^254 time **and** memory | `attacks/core_cryptanalysis.py` |
| Time-memory trade-off, worst case (break-point `p` known) | ~2^254 (508-bit state) | `attacks/period_census.py` (Part E) |
| Time-memory trade-off, realistic (`p` secret) | ~2^504 (≈1008-bit state) | same |
| Combined-orbit period before the ratchet even matters | ~2^247 per epoch | √M law, measured exponent 0.489 |

> **Claim: ~254-bit security.** We publish 254, not 256, because the meet-in-the-middle and the
> worst-case TMTO both land ~2 bits under a strict 256-bit line. The auto-rekey ratchet further
> starves any data-hungry trade-off by ~2^238 (an attacker never sees one long orbit to attack).
> The true ceiling is **key / KDF recovery** — not the chaos math and not the map count. That is
> exactly why we stopped at 4 maps: more maps add period and redundancy, not unbounded bit-security,
> because every map is seeded from the same 256-bit master key.

**What this claim is NOT:** it is not a proof, and it only covers the attacks we thought to run.
A structural weakness in the PWLCM itself that no one in this project has found would invalidate
it. That possibility is the entire reason for the outer-wall deployment and Phase 7 review.

---

## 4. Residual risks we are carrying forward

- **The divide-by-secret timing leak (#2)** — **CLOSED** in the Rust core (Phase 4 Stage B):
  precomputed-reciprocal multiply-shift, no hardware divide on the secret in the hot loop, measured
  0.41% timing spread across secret keys. See [CONSTANT_TIME.md](CONSTANT_TIME.md). (Note: the Python
  reference still divides — the constant-time guarantee lives in the Rust core, which is the build a
  real deployment would ship.)
- **Key zeroization** — CLOSED in the Rust core. The ratchet is ported (`RatchetEngine`, bit-identical
  to `ratchet.py` against the frozen KAT across re-key seams), and each retired chain key K_i is now
  overwritten with zeros in place (`zeroize`) the moment the chain steps past it — plus the stored live
  key is wiped on drop and each epoch key (MK_i) is wiped once the engine has absorbed it. This is the
  guarantee Python could only intend (immutable, GC'd `bytes`). *Honest residual:* transient stack
  copies of the **next** chain key (the one we keep anyway) and key-schedule buffers inside the vetted
  `hmac`/`sha2` crates are not scrubbed — eliminating those needs upstream zeroize support + stack
  hygiene, out of scope for a research core. The security-critical burn (the **retired** key) is done.
- **Key-commitment (#6)** — **CLOSED.** Both shells carry an explicit commitment (`commit.py`) that
  binds the blob to one key (CMT-4: key + salt + aad). Validated in `attacks/commitment_attack.py`:
  a blob never opens under a foreign key, and a measured birthday search confirms the collision cost
  tracks 2^(w/2) → ~2^128 at full width. *Honest note:* our HMAC-SHA256 tag was already a committing
  MAC, so we largely avoided the headline attack before this; the explicit field makes it provable and
  independent of any MAC-key-derivation subtlety. It is a SHELL property on vetted HMAC — the chaos
  keystream stays UNVETTED.
- **An unfound structural weakness in the chaos math** — possible, since it is unvetted. This is
  now contained by design: **two locks (`twolock.py`)** put the chaos cipher only as the OUTER wall
  over a vetted AES-256-GCM inner vault, so even a total chaos break leaves the data protected by a
  NIST-standard cipher. The chaos layer can fail outright and the client loses nothing. (Measured:
  `attacks/twolock_attack.py`.)
- **No external review yet** — the single largest risk. Self-attack found and fixed real bugs
  (a short-cycle weak-key class), which is encouraging, but it is not independent scrutiny. The
  two-lock deployment is what makes shipping an unreviewed cipher safe in the meantime.
