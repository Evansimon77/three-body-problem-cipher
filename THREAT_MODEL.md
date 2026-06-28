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
key while it is in use; and — most importantly — being the *only* lock. The intended deployment
(Phase 6, "Option B") puts this cipher as the OUTER wall over a vetted inner vault (AES-256-GCM
or XChaCha20-Poly1305), so if the chaos wall ever cracks the data is still fully protected.

---

## 2. The threats and how the design answers each

| Threat | Answer in the design | Where |
|---|---|---|
| **Keystream reuse** (two-time pad) | Fresh random nonce per message (AEAD), or a synthetic IV derived from the message itself (SIV) — two different messages can never share a keystream. | `aead.py`, `siv.py` |
| **Tampering / forgery** | Encrypt-then-MAC (HMAC-SHA256), verified in constant time before decrypting. | `aead.py` |
| **Wrong-key / garbage** | Same MAC check — fails closed, never returns plaintext. | `aead.py` |
| **Weak keys** | All key material passes a SHA-512 KDF; the weak-parameter band of `p` is rejected and remapped. A caller cannot pick a bad key. | `engine.from_master`, `engine.__init__` |
| **State roll-back / invertibility** | The raw linear state is never emitted: a nonlinear ARX finalizer + truncation (4 of 8 bytes) + the 4-map XOR hide each map's footprint. | `engine._finalize`, `multimap.py` |
| **Past-message recovery after a key leak** | Forward secrecy: the ratchet advances a one-way HMAC chain and burns the old key, so a live capture can't decrypt earlier epochs. | `ratchet.py` |
| **Period repetition** | Each 64 KiB epoch is a fresh ~2^247 orbit; re-keying dissolves the period limit, so usable length is effectively unbounded. | `ratchet.py` |
| **Man-in-the-middle on key agreement** | Triple-DH (static + ephemeral) authenticated exchange; a MITM lacking a party's static private key cannot derive the session key. | `auth_keyexchange.py` |
| **Timing side channel** | Both channels closed: the secret-dependent *branch* (mask-select, 1.0% spread) and the secret-dependent *divide* (Rust precomputed-reciprocal multiply-shift — measured 0.41% spread across 128 secret keys, no hardware divide on the secret in the hot loop). | [CONSTANT_TIME.md](CONSTANT_TIME.md), `rust/src/lib.rs` |

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
- **No external review yet** — the single largest risk. Self-attack found and fixed real bugs
  (a short-cycle weak-key class), which is encouraging, but it is not independent scrutiny.
