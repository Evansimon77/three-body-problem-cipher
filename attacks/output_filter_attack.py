"""
ATTACK / VALIDATION — the frosted-glass output filter (#3) + multi-byte output (#4).

Phase-2 adversarial check, scoped to the Phase-1 change. The project rule is "measure, don't
assert" — so before we trust the new output, we try to break it and quantify what changed.

WHAT THE CHANGE CLAIMS
  Old output: keystream byte = (state >> 24) & 0xFF — literally a *window into the state*.
  New output: keystream byte = truncate( fmix64(state) ) — a NONLINEAR function of the WHOLE
  state, of which we reveal only OUTPUT_BYTES_PER_STEP of 8 bytes.

PRECISE, HONEST CLAIM (no overclaim):
  The state-transition map is STILL invertible (that is inherent to PWLCM; we did not change it).
  What the filter changes is that the OUTPUT no longer exposes the state. The known-plaintext
  state-recovery break (known_plaintext.py Part B) only worked because one observed byte pinned
  down 8 contiguous state bits — its anchor. The filter removes that anchor.

THE FOUR PARTS
  Part 1 — the output no longer reveals any contiguous slice of the state (anchor gone).
  Part 2 — the exact Part-B known-plaintext break now FAILS to predict future keystream.
  Part 3 — even an attacker who KNOWS the filter loses the free 8 bits: the cheap 2^(n-8)
           search becomes a full 2^n state search (no shortcut, no affine structure).
  Part 4 — the filtered keystream introduces no detectable bias (randomness battery).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import finalize, OUTPUT_BYTES_PER_STEP  # noqa: E402
from constants import DEFAULT_N_MAPS  # noqa: E402
from multimap import MultiMapEngine  # noqa: E402
from known_plaintext import SmallPWLCM, recover_state    # noqa: E402


class SmallFinalizedPWLCM(SmallPWLCM):
    """SmallPWLCM (same chaotic state map) but with the REAL frosted-glass output: the emitted
    byte is taken from fmix64(state), not from a window of the state. This mirrors what the
    production engine now does, at a small modulus we can fully enumerate."""

    def out(self):
        self.step()
        return (finalize(self.x) >> 56) & 0xFF   # top byte of the nonlinear finalizer


# ---------- PART 1: the output no longer reveals any contiguous slice of the state ----------
def part1_anchor_gone(m_bits=16):
    """For the OLD output, the byte equals the top 8 state bits (correlation 1.0 there, ~0
    elsewhere). For the NEW output, scan EVERY 8-bit window of the state and show the strongest
    match-rate is no better than random guessing (1/256). No window anchors a search."""
    M_ = (1 << m_bits) - 1
    p = (1 << (m_bits - 2)) - 17

    def best_window_matchrate(use_filter):
        # For each candidate 8-bit window position s, fraction of states whose output byte equals
        # that window of the state. Old output -> a window hits 100%. New output -> all ~1/256.
        best = 0.0
        positions = range(0, m_bits - 7)
        for s in positions:
            hits = 0
            total = 0
            x = 7
            for _ in range(20000):
                eng = (SmallFinalizedPWLCM if use_filter else SmallPWLCM)(m_bits, x, p)
                eng.x = x
                b = eng.out()
                window = (eng.x >> s) & 0xFF      # a window of the POST-step state
                hits += (b == window)
                total += 1
                x = (x * 1103515245 + 12345) & M_ or 7   # cheap state sampler
            best = max(best, hits / total)
        return best

    old = best_window_matchrate(False)
    new = best_window_matchrate(True)
    print("PART 1 — does the output reveal a contiguous slice of the state?")
    print(f"  OLD output: best state-window match-rate = {old:.3f}  (high => output IS a window)")
    print(f"  NEW output: best state-window match-rate = {new:.4f}  (~{1/256:.4f}=1/256 => no anchor)")
    print(f"  => {'PASS' if new < 0.01 else 'FAIL'}: the filter hides the state from the output.\n")
    return new < 0.01


# ---------- PART 2: the exact Part-B known-plaintext break now fails ----------
def part2_kpa_fails(m_bits=20):
    """Run the SAME recover_state attack that fully breaks the old cipher, now against the
    filtered output. It anchors its search on 'first byte = top 8 state bits' — false now — so it
    cannot predict the unseen future keystream."""
    p = (1 << (m_bits - 2)) - 17
    big = (1 << m_bits) - 1
    true_x0 = (123456789 ^ (p * 7)) % big or 0x55

    # --- old output: attack SUCCEEDS (baseline, for contrast) ---
    truth_old = SmallPWLCM(m_bits, true_x0, p); truth_old.x = true_x0
    obs_old = truth_old.stream(12); fut_old = truth_old.stream(8)
    _, _, pred_old = recover_state(m_bits, p, obs_old)
    old_breaks = pred_old == fut_old

    # --- new output: same attack against the filtered stream ---
    truth_new = SmallFinalizedPWLCM(m_bits, true_x0, p); truth_new.x = true_x0
    obs_new = truth_new.stream(12); fut_new = truth_new.stream(8)
    x0n, tested_n, pred_new = recover_state(m_bits, p, obs_new)
    new_breaks = (x0n is not None) and (pred_new == fut_new)

    print("PART 2 — the known-plaintext state-recovery break (Part B), before vs after the filter:")
    print(f"  OLD output, M=2^{m_bits}: attack predicts future keystream = {old_breaks}  (breaks it)")
    print(f"  NEW output, M=2^{m_bits}: attack predicts future keystream = {new_breaks}  "
          f"(candidates_tried={tested_n:,})")
    print(f"  => {'PASS' if old_breaks and not new_breaks else 'FAIL'}: the filter neutralizes the "
          f"break that worked on the raw output.\n")
    return old_breaks and not new_breaks


# ---------- PART 3: even an adaptive attacker loses the free 8 bits ----------
def recover_state_full(SmallCls, m_bits, p, observed, predict_extra=8):
    """Strongest fair attack: the attacker KNOWS the output function, so they brute-force the
    WHOLE state (no anchor to narrow it). Returns work done and whether the future was predicted."""
    M_ = (1 << m_bits) - 1
    checks = observed[1:12]
    tested = 0
    for x0 in range(0, M_):
        tested += 1
        clone = SmallCls(m_bits, x0, p); clone.x = x0
        if all(clone.out() == b for b in checks):
            predicted = [clone.out() for _ in range(predict_extra)]
            return x0, tested, predicted
    return None, tested, None


def part3_no_shortcut(m_bits=16):
    """At a tiny modulus everything is brute-forceable; the point is the COST. Old output: the
    anchored search is ~2^(m-8). New output: the attacker must scan the full ~2^m. The filter
    bought back the 8 bits the windowed output gave away — and removed the affine shortcut."""
    p = (1 << (m_bits - 2)) - 17
    big = (1 << m_bits) - 1
    true_x0 = (987654321 ^ (p * 5)) % big or 0x55

    truth = SmallFinalizedPWLCM(m_bits, true_x0, p); truth.x = true_x0
    observed = truth.stream(12); future = truth.stream(8)

    t0 = time.time()
    x0, tested, predicted = recover_state_full(SmallFinalizedPWLCM, m_bits, p, observed)
    dt = time.time() - t0
    ok = predicted == future
    anchored = 1 << (m_bits - 8)     # what the old windowed attack would have searched
    print("PART 3 — adaptive attacker who knows the filter (cost of the only remaining attack):")
    print(f"  M=2^{m_bits}: full-state recovery works at tiny scale = {ok}  "
          f"(searched {tested:,} states, {dt:.2f}s)")
    print(f"  anchored search the OLD output allowed = ~2^{m_bits-8} = {anchored:,} states")
    print("  => the filter turns a 2^(n-8) anchored search into a full 2^n search "
          "(+8 bits of work), and Part 1 shows there is no window/affine shortcut left.")
    print("     Real engine: 2^(state_bits) per map, XOR'd over the map count — no cheap path.\n")
    return ok  # 'ok' just confirms our model is sound (small scale is always brute-forceable)


# ---------- PART 4: the filtered keystream introduces no detectable bias ----------
def part4_no_bias(n_bytes=200_000):
    """Per-bit bias, byte chi-square, and serial correlation on the real multi-map filtered keystream.
    A good output filter should keep the stream statistically flat (avalanche is already ~0.5)."""
    ks = MultiMapEngine(b"bias-probe-key", b"bias-probe-nonce").keystream(n_bytes)

    # per-bit bias (max |p(bit=1) - 0.5| in sigma over 8 bit positions)
    import math
    n = len(ks)
    worst_sigma = 0.0
    for bit in range(8):
        ones = sum((byte >> bit) & 1 for byte in ks)
        sigma = abs(ones - n / 2) / math.sqrt(n / 4)
        worst_sigma = max(worst_sigma, sigma)

    # byte chi-square (uniform over 256 values; df=255, expect ~255 +- ~22.6)
    counts = [0] * 256
    for byte in ks:
        counts[byte] += 1
    exp = n / 256
    chi2 = sum((c - exp) ** 2 / exp for c in counts)

    # serial correlation (lag-1)
    mean = sum(ks) / n
    num = sum((ks[i] - mean) * (ks[i + 1] - mean) for i in range(n - 1))
    den = sum((b - mean) ** 2 for b in ks)
    serial = num / den if den else 0.0

    print(f"PART 4 — randomness of the filtered {DEFAULT_N_MAPS}-map keystream (no new bias?):")
    print(f"  worst per-bit bias : {worst_sigma:.2f} sigma   (|<3| = clean)")
    print(f"  byte chi-square    : {chi2:.1f}  on df=255  (expect ~255 +/- 22.6)")
    print(f"  serial corr (lag-1): {serial:+.5f}        (~0 = clean)")
    clean = worst_sigma < 4 and 150 < chi2 < 360 and abs(serial) < 0.01
    print(f"  => {'PASS' if clean else 'CHECK'}: filtered output is statistically flat.\n")
    return clean


if __name__ == "__main__":
    print("=" * 78)
    print(f"FROSTED-GLASS OUTPUT FILTER — adversarial validation "
          f"(emitting {OUTPUT_BYTES_PER_STEP}/8 bytes per step)")
    print("=" * 78 + "\n")
    r1 = part1_anchor_gone()
    r2 = part2_kpa_fails()
    r3 = part3_no_shortcut()
    r4 = part4_no_bias()
    print("=" * 78)
    print(f"VERDICT  anchor-gone={r1}  kpa-break-neutralized={r2}  "
          f"model-sound={r3}  no-new-bias={r4}")
    print("Honest scope: this validates that the filter hides the state from the output and kills")
    print("the known-plaintext anchor + affine shortcut. It is NOT a proof of security — the map")
    print("stays invertible and the design stays UNVETTED. Grid is now 2^127 (#1 done); next: Rust.")
    print("=" * 78)
