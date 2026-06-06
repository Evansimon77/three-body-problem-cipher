# REPORT — Adversarial Evaluation of the Chaos PWLCM Cipher

**Date:** 2026-06-06
**Subject:** Discretized pure-integer PWLCM keystream cipher (`engine.py`), modulus `M = 2^61 - 1`.
**Method:** Build the proposed design faithfully, then try to break it and measure it against
real standards. "Proven" = survived; "broken" = it didn't.

---

## TL;DR verdict

The core idea is **sound enough to be interesting and demonstrably synchronizes across machines**
(the integer-math fix for the finite-precision problem genuinely works). On the screens we ran,
the keystream looks statistically clean and has textbook ~50% avalanche.

But the **strong claims in the original write-up are false or overstated**, and adversarial
testing found **three real problems**:

1. **Trivially broken by keystream reuse** (two-time pad) — fully demonstrated.
2. **Weak-key / weak-parameter classes exist** — e.g. `control=1, key=1` collapses to **period 1**.
3. **The map is invertible** — "no structure to exploit / no clues" is simply not true; a full
   state-recovery works at reduced scale and is a *key-size* argument, not magic, at full scale.

It is also **~700–800× slower** than AES/ChaCha. **Bottom line: do not use this to protect real
data.** It is a good learning artifact, not a cipher you'd trust.

---

## Results by test (all numbers measured on this machine, Python 3.14)

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 1 | Correctness / determinism (`pytest`) | 8/8 pass; two instances produce identical keystream | ✅ PASS — cross-machine sync works |
| 2 | **Period** (Brent) | Normal keys: no cycle in 2,000,000-step budget. **`key=1,ctrl=1` → period 1 (FATAL)** | ⚠️ MOSTLY OK, **weak-key class found** |
| 3 | Avalanche | key-bit flips mean **0.5000** (min .493/max .506); nonce-bit **0.4996** | ✅ PASS — excellent diffusion |
| 4 | Randomness (NIST-lite, 1.6M bits) | monobit p=0.52, runs p=0.77, block-freq p=0.94; byte χ²=251 (ideal ~255) | ✅ PASS (screen only — see caveat) |
| 5 | **Two-time pad** (reuse key+nonce) | `C1⊕C2 = P1⊕P2`; **both plaintexts fully recovered** | ❌ BROKEN (usage) — nonces mandatory |
| 6 | **Known-plaintext / state recovery** | Map invertible (predecessor recovered, off-by-1). Full recovery + future-keystream prediction at M=2²⁰ and M=2²⁴ | ❌ BROKEN at small scale; key-size-safe at full scale |
| 7 | Speed | chaos **2.6 MB/s** vs AES-256-CTR **2047 MB/s**, ChaCha20 **1888 MB/s** | ❌ ~786× / ~725× slower |

---

## Original claims vs. reality

| Claim in the write-up | Reality (measured) |
|------------------------|--------------------|
| "Mathematically unhackable by brute force" | Brute force isn't the only attack. **Keystream reuse breaks it instantly** (test 5); the map is **invertible** (test 6). |
| "No gradient / no clues — a miss by 1 looks like a miss by a billion" | True for *guessing the key blind* (avalanche ≈ 0.5 confirms it), but **irrelevant to real cryptanalysis**, which exploits algebraic structure, not "warmth". Structure exists. |
| "Quantum-resistant because it doesn't factor primes" | Non-claim. **All** symmetric stream ciphers (AES, ChaCha) are already ~quantum-resistant (Grover = quadratic only). Nothing special here. A weak cipher is weak regardless of quantum. |
| "Inherently non-repeating due to chaos" | **False for the integer version.** A finite state space *must* cycle (pigeonhole). Normal keys have a long-enough period in our budget, but **degenerate parameters cycle immediately** (test 2). |
| Solves finite-precision via integer math | **TRUE and the best part.** Determinism across instances confirmed (test 1). This is the one claim that fully holds. |
| "Passwordless, un-stealable logins" | Misleading. Stored initial conditions = a stored shared secret. Steal the DB + know the algorithm (assume yes, Kerckhoffs) ⇒ it's a stored password. |

---

## The three real findings (detail)

**1. Two-time pad (the practical killer).** XOR stream ciphers die if the keystream repeats.
Encrypting two messages under the same `(key, nonce)` cancels the keystream: `C1⊕C2 = P1⊕P2`,
and both plaintexts fall out by crib-dragging. We recovered a full secret message with **zero
key knowledge**. This is the most likely way the scheme dies in practice and is *independent* of
how good the chaos is. Mitigation: a unique nonce per message, never reused — already in the API,
but it's a footgun the moment anyone forgets.

**2. Weak-key / weak-parameter classes.** `control=1, key=1` collapses to a **fixed point
(period 1)** — constant keystream. A real cipher must have no such classes, or must reject them.
This one needs key/parameter validation that the current design lacks.

**3. Invertibility / structure.** Each PWLCM branch is an affine map `x → M·(x−a)//d`, hence
invertible up to the integer-division remainder. We recovered a predecessor state off-by-1, and
ran a **full state-recovery** on small-modulus clones (M=2²⁰, 2²⁴): from known plaintext we
reconstructed the internal state and **correctly predicted future keystream**. The cost scales
as ~`2^(state_bits − 8)` (× the keyspace of `p` if secret), so the *full* 61-bit engine resists
this *particular naive* attack — but only by a **key-size argument**, exactly like a normal
cipher, **not** the claimed "no possible attack." PWLCM ciphers are an active cryptanalysis
target and several published variants have been broken.

---

## What's genuinely good

- The **integer-math determinism works** — the keystream is bit-identical across instances,
  solving the finite-precision paradox that kills floating-point chaos ciphers.
- **Avalanche ≈ 0.5** and the keystream **passes the randomness screen** — the generator is a
  decent *PRNG*. (Good PRNG ≠ secure cipher; e.g. Mersenne Twister is great statistically and
  cryptographically broken.)

## What would be required to make it trustworthy (and why you shouldn't bother)

Reject weak keys, add a nonce-misuse-resistant construction, add authentication (a MAC — XOR
ciphers are malleable), then submit it to *years* of public cryptanalysis. That is exactly the
process AES and ChaCha20 already went through. **Recommendation for any real use:** keep this as
a research toy; do the actual encryption with a vetted primitive
(`ChaCha20-Poly1305` / `AES-GCM` / libsodium). If you want the chaos for fun, run it as a *layer
on top of* a vetted cipher, never as the only thing standing between an attacker and the data.

---

## v2 update — AEAD shell added (weak-key rejection + MAC)

After the evaluation above, two structural fixes were added via a `seal()`/`open_()` layer
(`aead.py`) that wraps the unchanged chaos core. What changed:

| Finding | Before | After v2 |
|---|---|---|
| #2 Weak-key collapse (`key=1,ctrl=1` → period 1) | FATAL | **Fixed.** Weak-parameter band rejected; keys go through a hash KDF (`from_master`). Period test now shows no collapse. |
| Malleability / tampering | unprotected | **Fixed.** Encrypt-then-MAC (HMAC-SHA256), constant-time verify. `test_aead.py`: tamper, truncation, wrong-key, AAD-mismatch all rejected (10/10 pass). |
| #1 Two-time pad | instant break | **Fixed in practice.** `seal()` draws a fresh random nonce每 call, so reuse can't happen via the safe API. (The raw map still reuses if you force a nonce — that's why you use `seal()`.) |
| #3 Invertible map / state recovery | broken at small scale | **Unchanged.** This is the core math; the shell doesn't touch it. Security here is still a key-size argument, not a proof. |
| Speed | ~700–800× slower | Unchanged-to-slightly-worse (MAC adds a little). |
| **Unvetted by cryptographers** | true | **Still true — the only thing that ultimately matters.** |

**Net:** v2 takes the engine from "a broken toy" to "a structurally complete, correctly-shaped
AEAD cipher" — same *shape* as ChaCha20-Poly1305. It is now a legitimate research/portfolio
artifact. It is still **not** proven-secure and still should **not** guard real client data;
for that, use a vetted AEAD and run the chaos as a layer on top if you want it.

## v3 update — multi-map (3 independent PWLCMs, XOR-combined)

The biggest open weakness was #3: the single map is invertible, so the known-plaintext
state-recovery (Part B) breaks it at reduced scale. v3 implements the "three-body" fix as
**3 independent maps XOR-combined** (`multimap.py`, `MultiMapEngine`, now the default keystream in
`seal()`/`open_()`).

| Aspect | Result |
|---|---|
| **#3 state-recovery** | **Mitigated.** `attacks/known_plaintext.py` Part C runs the *same* attack vs the 3-map stream: at M=2²⁰ and M=2²⁴ the single-map recovery **cannot predict future keystream** (where it *did* break the single map). Naive joint brute-force jumps to ~2^159. |
| Why it works | Output = `b1⊕b2⊕b3`; the attacker can't separate the three states, so each map's invertibility footprint is hidden behind the other two. Maps are **independent (uncoupled)** — no chaos-synchronization risk. |
| Correctness/auth | `tests/` 25/25 pass (incl. `test_multimap.py`); AEAD unchanged and still green. |
| Avalanche / cycles | Multi-map avalanche ≈ 0.5; no short cycle in a 100 KB sample. |
| Speed | 3-map ≈ **3.3× slower** than 1-map (≈ 0.8 MB/s) — the honest, expected cost; ~3000× slower than AES/ChaCha. |
| Still true | **UNVETTED.** XOR-combining defeats the *naive per-map* attack; it is not a security proof. More advanced per-component cryptanalysis remains possible. Independence relies on the domain-separated KDF (`multimap._derive_engine`). |

**Net:** the specific attack we demonstrated no longer breaks the cipher, and we *measured* that —
exactly the "prove it" goal. Nesting / N>3 was deliberately **not** adopted (cost + complexity +
sync risk for no real security gain past the brute-force wall); it stays a possible future
*measured* experiment only.

## v4 update — seekable CTR mode (`ctr.py`, `SeekableCTR`)

A *capability* upgrade, not a security claim. The streaming engines are a tape — to read byte N you
must generate 0..N-1. v4 adds counter mode: the keystream is cut into fixed `BLOCK_SIZE` blocks, and
block *i* is derived independently from `(master_key, nonce, block_index=i)` via the same
domain-separated SHA-512 KDF (block counter folded in). Exactly the AES-CTR construction, with the
3-map chaos keystream as the PRF.

| Aspect | Result |
|---|---|
| **Random access** | `keystream(n, offset=k)` returns global bytes `k..k+n-1`; only the covering block(s) are derived. `test_ctr.py::test_random_access_skips_earlier_blocks` confirms reading at position 1,000,000 derives **one** block, not a million. |
| **Correctness** | Windowed reads match the full-stream slice across block boundaries; offset round-trips. `tests/` 35/35 pass (10 new in `test_ctr.py`). |
| **Separation** | Distinct blocks are domain-separated ⇒ unrelated keystreams (strictly *more* separation than the streaming map's single continuous orbit). Avalanche ≈ 0.5; no short cycle in 100 KB. |
| **Cost** | Each block pays a fresh KDF + warmup ⇒ CTR ≈ **1.2× slower** than the streaming 3-map (≈ 0.64 MB/s) at `BLOCK_SIZE=64`. The honest price of seekability + parallelizability. |
| Still true | **UNVETTED.** Seekability is an engineering property; it inherits — and does not improve — the underlying chaos security. |

**Net:** the cipher is now random-access addressable (decrypt the middle of a large file, or
parallelize) while keeping every prior property. Security is unchanged; this is about usability.

## Reproduce

```bash
pip install -r requirements.txt
pytest tests/ -v
python ctr.py
python tests/test_period.py
python tests/test_avalanche.py
python bench/nist_lite.py
python attacks/two_time_pad.py
python attacks/known_plaintext.py
python bench/speed.py
```
