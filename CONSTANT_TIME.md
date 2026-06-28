# Constant-time specification

A cipher leaks if the *time* it takes depends on the *secret*. An attacker who can measure
timing can claw back key bits without ever breaking the math. This document is the contract for
keeping the chaos core constant-time. Both timing channels in the PWLCM step are now **closed**:
the secret-dependent branch (Phase 0, Python) and the secret-dependent divide (Phase 4 Stage B,
Rust). This document records each, how it was closed, and how it was measured.

The numbers below come from `bench/timing_leak.py` (branch leak, Python) and `chaos_core timing`
(divide leak, Rust) — run either to reproduce. **Measured, not asserted.**

---

## The two timing channels in the PWLCM step

The per-byte hot path is one PWLCM step (`engine._next_state`). It has historically had two
places where the secret could influence timing:

### 1. The secret-dependent BRANCH — CLOSED ✅

The original map chose one of four linear segments with an `if/elif` chain keyed on the secret
state. Different branches can take different time, so the *time* revealed *which region the
secret state was in*.

**Fix (already in `engine.py`):** evaluate **all four** candidate next-states every step and
keep the right one with 0/1 masks. Same work regardless of the secret — no branch to time.

**Measured:** stepping with the state pinned to each of the four regions gives **1.0% spread**
across regions — within scheduler noise. The branch leak is closed.

```
region (0, p)      1228 ns/step
region [p, HALF)   1216 ns/step
region [HALF, M-p) 1224 ns/step
region [M-p, M)    1224 ns/step
-> 1.0% spread (within noise)
```

### 2. The secret-dependent DIVIDE — CLOSED ✅ (Rust, Phase 4 Stage B)

The old map computed `(M * x) // p` and `… // (HALF - p)` every step. The divisors `p` and
`HALF - p` are derived from the secret, and on real CPUs integer-division latency is
*data-dependent* — so a native build would leak information about `p` through timing.

**Why Python couldn't see it:** varying `p` across its whole legal band gave only **3.6%** spread
at the Python level — no clean signal, because CPython's interpreter overhead (~1200 ns/step)
swamped the hardware divide (a few ns). The leak was real but invisible in the reference; it would
have surfaced the moment the hot loop went native.

**Fix (Rust `rust/src/lib.rs`, Stage B):** there is **no hardware divide on the secret in the hot
loop**. At key setup we precompute a scaled reciprocal `V = floor(M · 2¹²⁷ / d)` once for each of
the two fixed divisors `d ∈ {p, HALF − p}` (the only divides by the secret, and they run once per
key, not per byte). Each per-step "division" is then `q = ((num · V) >> 127) + correction`, where
the single branchless correction (add 1 iff the remainder is still `≥ den`) is provably exact —
the truncation error is `< ½` because every divisor is `< 2¹²⁶`. The hot loop now executes only
fixed-width multiplies, shifts, adds, masked compares, and a branchless `select` for the
reciprocal — the same instruction sequence regardless of the secret.

**Measured (native, `chaos_core timing 128`):** timing 128 different secret keys, each key's
per-byte compute floor (min over 15 reps, so OS/cache noise only adds):

```
ns/byte floors:  min 4.721   median 4.731   p95 4.741   max 4.771
secret-dependent spread (p95 − min)/median:  0.41%   (raw max − min: ~1%)
```

Flat across every secret — no key-dependent timing. (A first pass with a naive `(max−min)/mean`
metric reported 39% off a single scheduler hiccup; the robust min-of-reps + percentile spread
shows that was noise, not signal — the same cry-wolf lesson as the Phase-1 ratchet seam test.)
**The divide leak is closed, and measured closed — not hidden by noise.**

---

## The Rust-port requirement (Phase 4, §4 precomputed reciprocal) — IMPLEMENTED

> Status: **DONE** in `rust/src/lib.rs` (Stage B). This section is kept as the spec the
> implementation was held to; deviations from the original plan are noted at the end.

The Rust core MUST NOT emit a hardware divide instruction whose divisor is the secret. Replace
both `// p` and `// (HALF - p)` with a **precomputed-reciprocal multiply-shift**:

1. At **key setup** (once, not per byte), compute reciprocal constants for the two fixed
   divisors `p` and `HALF - p` — Barrett or Montgomery reduction. Both divisors are guaranteed
   `> 0` (`p ∈ [MIN_P, HALF - MIN_P]`), so the reciprocal is always well-defined.
2. In the **hot loop**, each "division" becomes a wide multiply by the precomputed constant plus
   a fixed shift/correction — all data-independent, fixed-width operations. No `div` instruction
   with a secret operand ever executes per byte.

Supporting constant-time requirements for the port:

- **Wide multiply.** With `M = 2^127 − 1`, products `M * x` reach ~254 bits. The port must do a
  128×128→256-bit multiply (or fold it into the Barrett/Montgomery reduction) at fixed width —
  width is constant, never secret-dependent.
- **Mask-select, not branch.** Keep the four-candidate + 0/1-mask structure from the Python
  reference; do not "optimize" it back into a branch.
- **Mask-select, not branch.** Constant-time selects/compares; never a plain `if` on secret data.
- **`zeroize` old keys.** Wipe the burned ratchet chain key in place (the Python reference can
  only drop the reference, not guarantee the wipe).

### Deviations from the original plan (honest notes)

- **Barrett, not Montgomery.** A scaled-reciprocal (Barrett-style) multiply-shift was used. It
  needs only one precompute divide per divisor and one branchless correction per step — simpler
  than Montgomery for this fixed-divisor case, and exact (proven, and checked against the big-int
  oracle over ~4.8M random pairs in `recip_div_matches_bigint_oracle`).
- **`ruint` U256 + hand-rolled `select`, not the `subtle` crate.** The wide math uses `ruint`'s
  fixed-width U256 (multiply/shift/compare are fixed-instruction on 4 limbs — no early-out), and
  the reciprocal is chosen by a branchless limb-wise `select` rather than `subtle`. Equivalent
  constant-time property; one fewer dependency. `ruint`'s variable-time `/` and `%` survive ONLY
  off the hot path (reciprocal precompute + the once-per-key init avalanche), where a single
  variable-time op per key is the accepted norm (cf. OpenSSL/GMP reciprocal setup).
- **`zeroize` is still pending** — the ratchet/key-chain isn't ported to Rust yet (Phase 4 later
  item), so there's no burned key to wipe in the Rust core today.

---

## How this is verified

- **Branch leak (Python):** `bench/timing_leak.py` confirms it closed (1.0% spread).
- **Divide leak (Rust):** `chaos_core timing <keys>` times the native hot loop across many secret
  keys and reports the per-byte spread — **0.41%** across 128 keys, i.e. no key-dependent timing
  because the divide is gone, not because noise hides it (§2 above).
- **Bit-identity:** the Rust core reproduces every `engine_raw` vector in `kat/vectors.json`
  byte-for-byte (`tests/test_rust_parity.py`, 3/3) — so closing the leak did **not** change the
  cipher's output. The reciprocal path is also checked against the big-int oracle directly
  (`cargo test recip_div_matches_bigint_oracle`, ~4.8M pairs).

The divide leak (timing leak #2) is now **closed and measured closed**.
