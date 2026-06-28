# Constant-time specification

A cipher leaks if the *time* it takes depends on the *secret*. An attacker who can measure
timing can claw back key bits without ever breaking the math. This document is the contract for
keeping the chaos core constant-time: what is already done, what is still open, and exactly how
the Rust port (Phase 4) must close the gap.

The numbers below come from `bench/timing_leak.py` (run it to reproduce). **Measured, not asserted.**

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

### 2. The secret-dependent DIVIDE — OPEN, deferred to Rust ⏳

Each step still computes `(M * x) // p` and `… // (HALF - p)`. The divisors `p` and `HALF - p`
are derived from the secret. On real CPUs, integer-division latency is *data-dependent* — so a
native build leaks information about `p` through timing.

**Measured at the Python level:** varying `p` across its whole legal band gives only **3.6%**
spread — no clean signal, because CPython's interpreter overhead (~1200 ns/step) swamps the
hardware divide (a few ns). So **the leak is NOT exploitable in the Python reference** — but it
is real, and it WILL be exposed once the hot loop is native and the interpreter overhead is gone.

This is an honest "the floor is too noisy to see it here, not the leak isn't there." The fix
belongs where the leak becomes visible: the Rust core.

---

## The Rust-port requirement (Phase 4, §4 precomputed reciprocal)

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
- **Use `subtle`.** Constant-time selects/compares via the `subtle` crate; never a plain `if` on
  secret data.
- **`zeroize` old keys.** Wipe the burned ratchet chain key in place (the Python reference can
  only drop the reference, not guarantee the wipe).

---

## How this is verified

- **Today:** `bench/timing_leak.py` confirms the branch leak is closed and quantifies the
  (Python-masked) divide leak.
- **At the port:** the Rust core must (a) reproduce every vector in `kat/vectors.json` bit-for-bit
  (see [README / §3 KAT](kat/generate_kat.py)) AND (b) pass a divisor-timing test analogous to
  the one here, now showing no signal because the divide is gone — not because noise hides it.

Until the port lands, the divide leak is a **documented, carried risk** (see
[THREAT_MODEL.md](THREAT_MODEL.md) §4), not a closed item.
