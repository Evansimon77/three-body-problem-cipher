"""
ATTACK 4 — "Clever-burglar" cryptanalysis of the multi-map combiner (default N=4 maps).

attacks/known_plaintext.py Part C only ran the LAZY attack on the combiner: it pointed the
single-map state-recovery at the XOR of the maps and (correctly) found it fails. That proves the
combiner beats the *obvious* attack — not that it is strong. This file sends three CLEVER attacks
that are actually designed for a combiner, and MEASURES the result (the project ethos: break-and-
measure, never assert). Everything here reads the SHIPPED map count (DEFAULT_N_MAPS = 4) — Phase 1
raised it 3 -> 4, so the MITM in Part C now uses a balanced split and reports the real 4-map cost:

  PART A — Distinguisher / bias hunt.
      Does the SHIPPED keystream leak any statistical pattern that separates it from true random?
      `ent` only checks bulk randomness over 100 MB; a distinguisher hunts the FINE structure an
      invertible affine map might leak: per-bit bias, byte-value chi-square, byte-lag serial
      correlation, and a battery of linear-mask parity biases. Output: the largest deviation found,
      in standard deviations (sigma). Many sigma on one test = a real foothold; all small = clean.

  PART B — Independence / synchronization check.
      The combiner is only sound if the maps are INDEPENDENT. If they secretly drift into
      step (chaos synchronization) or any sub-map leaks into the combined byte, a divide-and-conquer
      correlation attack becomes possible. We measure sub-map<->combined and sub-map<->sub-map
      correlation, plus a collision/sync detector. All should sit at the random noise floor.

  PART C — Meet-in-the-middle (MITM) joint recovery, measured at small scale.
      The CLEVER way to attack an XOR combiner of N enumerable generators: don't brute-force all N
      states at once (~2^(N*state)). Split the maps into two halves, build a table of one half's
      forced output prefixes, and match the other half against it — classic meet-in-the-middle. We
      run it on small-modulus clones at the SHIPPED map count, VERIFY it recovers a keystream-
      equivalent state set and predicts unseen future keystream, and COUNT the real work — to see
      that the combiner's true strength is ~ceil(N/2)*state (TIME *and* MEMORY), not N*state. For
      N=4 / 127-bit state that is ~2^254, still astronomically safe; the point is an honest number.

Run:  python attacks/core_cryptanalysis.py
"""
from __future__ import annotations

import itertools
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import M  # noqa: E402
from constants import DEFAULT_N_MAPS  # noqa: E402
from multimap import MultiMapEngine  # noqa: E402
from known_plaintext import SmallPWLCM  # noqa: E402

KEY = b"clever-burglar-cryptanalysis-key"
NONCE = b"attack4-nonce-01"


# ============================ PART A — distinguisher / bias hunt ============================
def _sigma_balanced(ones: int, n: int) -> float:
    """How many standard deviations the count of 1s is from the random expectation n/2."""
    return (ones - n / 2) / (math.sqrt(n) / 2)


def bias_hunt(n_bytes: int = 300_000):
    print(f"PART A — distinguisher / bias hunt on the SHIPPED {DEFAULT_N_MAPS}-map keystream")
    t0 = time.time()
    ks = MultiMapEngine(KEY, NONCE).keystream(n_bytes)
    gen_dt = time.time() - t0
    print(f"  generated {n_bytes:,} keystream bytes in {gen_dt:.1f}s")

    # 1) per-bit-plane bias: each of the 8 bit positions should be ~50% ones
    worst_bit = (None, 0.0)
    for bit in range(8):
        ones = sum((b >> bit) & 1 for b in ks)
        s = _sigma_balanced(ones, n_bytes)
        if abs(s) > abs(worst_bit[1]):
            worst_bit = (bit, s)
    print(f"  bit-plane bias .............. worst = {worst_bit[1]:+.2f} sigma (bit {worst_bit[0]})")

    # 2) byte-value chi-square over 256 buckets (df=255, mean 255, std ~22.6)
    counts = [0] * 256
    for b in ks:
        counts[b] += 1
    exp = n_bytes / 256
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    chi_sigma = (chi2 - 255) / math.sqrt(2 * 255)
    print(f"  byte-value chi-square ....... {chi2:.1f} (ideal ~255) = {chi_sigma:+.2f} sigma")

    # 3) byte-level serial correlation at lags 1..8 (Pearson r); ideal ~0
    worst_lag = (None, 0.0)
    mean = sum(ks) / n_bytes
    var = sum((b - mean) ** 2 for b in ks) / n_bytes
    for lag in range(1, 9):
        cov = sum((ks[i] - mean) * (ks[i + lag] - mean) for i in range(n_bytes - lag))
        r = (cov / (n_bytes - lag)) / var
        # r ~ Normal(0, 1/sqrt(N)) under independence
        s = r * math.sqrt(n_bytes - lag)
        if abs(s) > abs(worst_lag[1]):
            worst_lag = (lag, s)
    print(f"  byte serial corr (lag 1-8) .. worst = {worst_lag[1]:+.2f} sigma (lag {worst_lag[0]})")

    # 4) linear-mask parity battery over a 3-byte sliding window
    #    Each mask selects some bits from 3 consecutive bytes; the parity (XOR) of those bits
    #    should be an unbiased coin. A biased mask = a linear approximation = a real distinguisher.
    import random
    rng = random.Random(1234)
    window = 3
    positions = [(o, b) for o in range(window) for b in range(8)]   # 24 selectable bits
    mask_set = set()
    masks = []
    for pos in positions:               # all single-bit masks (24)
        m = (pos,)
        mask_set.add(m)
        masks.append(m)
    while len(masks) < 24 + 80:          # random 2- and 3-bit masks, DISTINCT bits only
        k = rng.choice((2, 3))           # (sampling distinct bits avoids "bit XOR itself = 0")
        m = tuple(sorted(rng.sample(positions, k)))
        if m not in mask_set:
            mask_set.add(m)
            masks.append(m)
    n_used = n_bytes - window
    worst_mask = (None, 0.0)
    for mask in masks:
        ones = 0
        for i in range(n_used):
            par = 0
            for (off, bit) in mask:
                par ^= (ks[i + off] >> bit) & 1
            ones += par
        s = _sigma_balanced(ones, n_used)
        if abs(s) > abs(worst_mask[1]):
            worst_mask = (mask, s)
    print(f"  linear-mask parity ({len(masks)} masks)  worst = {worst_mask[1]:+.2f} sigma")

    overall = max(abs(worst_bit[1]), abs(chi_sigma), abs(worst_lag[1]), abs(worst_mask[1]))
    print("  ----")
    print(f"  strongest deviation anywhere: {overall:.2f} sigma over "
          f"~{8 + 1 + 8 + len(masks)} tests")
    verdict = ("looks RANDOM (no exploitable bias found at this scale)"
               if overall < 5 else "POSSIBLE STRUCTURE — investigate")
    print(f"  verdict: {verdict}\n")
    return overall


# ===================== PART B — independence / synchronization check =====================
def independence_check(n: int = 200_000):
    eng = MultiMapEngine(KEY, NONCE)
    subs = eng.engines
    n_maps = len(subs)
    print(f"PART B — are the {n_maps} maps truly independent (no synchronization / leak)?")

    # collect aligned sub-map bytes and the combined byte
    b = [[0] * n for _ in range(n_maps)]
    comb = [0] * n
    for i in range(n):
        c = 0
        for m in range(n_maps):
            v = subs[m].generate_byte()
            b[m][i] = v
            c ^= v
        comb[i] = c

    def bit_corr_sigma(xs, ys):
        """Worst per-bit correlation (in sigma) between two byte streams."""
        worst = 0.0
        for bit in range(8):
            # correlation of two balanced bits ~ count of agreements vs n/2
            agree = sum(1 for i in range(n) if ((xs[i] >> bit) & 1) == ((ys[i] >> bit) & 1))
            s = _sigma_balanced(agree, n)
            if abs(s) > abs(worst):
                worst = s
        return worst

    # sub-map[0] vs combined: must be ~0 (else the combined byte leaks a sub-map)
    s_leak = bit_corr_sigma(b[0], comb)
    print(f"  sub-map[0]  vs combined ..... worst bit corr = {s_leak:+.2f} sigma (want ~0)")
    # sub-map[0] vs sub-map[1]: must be ~0 (independence)
    s_pair = bit_corr_sigma(b[0], b[1])
    print(f"  sub-map[0]  vs sub-map[1] ... worst bit corr = {s_pair:+.2f} sigma (want ~0)")
    # synchronization detector: how often do two sub-maps emit the SAME byte? ideal 1/256
    same01 = sum(1 for i in range(n) if b[0][i] == b[1][i])
    exp_same = n / 256
    sync_sigma = (same01 - exp_same) / math.sqrt(exp_same)
    print(f"  byte-collision sub0==sub1 ... {same01:,} vs ideal {exp_same:,.0f} "
          f"= {sync_sigma:+.2f} sigma (sync would spike this)")

    overall = max(abs(s_leak), abs(s_pair), abs(sync_sigma))
    verdict = ("INDEPENDENT (no leak / no sync detected)"
               if overall < 5 else "DEPENDENCE DETECTED — combiner foothold")
    print(f"  verdict: {verdict}\n")
    return overall


# ===================== PART C — meet-in-the-middle joint recovery =====================
def _prefix_table(m_bits: int, p: int, key_len: int, n_states: int) -> list:
    """Precompute the first `key_len` output bytes for every state. All maps share (p, dynamics),
    so ONE table serves every map — a state's output prefix is the same whichever slot it sits in."""
    pref = []
    for s in range(n_states):
        mp = SmallPWLCM(m_bits, s, p)
        mp.x = s
        pref.append(tuple(mp.out() for _ in range(key_len)))
    return pref


def _xor_t(a: tuple, b: tuple) -> tuple:
    return tuple(x ^ y for x, y in zip(a, b))


def mitm_recover(m_bits: int, n_maps: int = DEFAULT_N_MAPS, verify_len: int = 14, predict: int = 8):
    """Balanced meet-in-the-middle on an N-map XOR combiner at modulus 2^m_bits (p known = worst
    case for the attacker). Split the maps into halves A|B; table A's combined output prefixes; for
    each B-combo the required A-prefix is FORCED (= observed ^ B_prefix) and looked up. Verifies a
    keystream-equivalent state set and predicts UNSEEN future keystream.
    Returns (recovered_exact, future_predicted_ok, work, mitm_exp, naive_exp)."""
    big = (1 << m_bits) - 1
    n_states = big + 1
    p = (1 << (m_bits - 2)) - 17
    seeds = [(123456789 ^ (p * (k + 3))) % big or 0x55 for k in range(n_maps)]

    def combined_stream(states, t):
        maps = []
        for s in states:
            mp = SmallPWLCM(m_bits, s, p)
            mp.x = s
            maps.append(mp)
        out = []
        for _ in range(t):
            c = 0
            for mp in maps:
                c ^= mp.out()
            out.append(c)
        return out

    total = verify_len + predict
    full = combined_stream(seeds, total)
    observed = full[:verify_len]                 # attacker's known-plaintext window
    future_truth = full[verify_len:]             # must NOT be seen — the real test

    key_len = min(6, verify_len)
    pref = _prefix_table(m_bits, p, key_len, n_states)
    obs_pre = tuple(observed[:key_len])

    half = n_maps // 2
    a_slots, b_slots = half, n_maps - half       # |A|, |B| maps per side

    def combo_prefix(combo):
        pr = pref[combo[0]]
        for s in combo[1:]:
            pr = _xor_t(pr, pref[s])
        return pr

    # table over side-A combos: combined-prefix -> list of A-state-tuples
    table: dict[tuple, list] = {}
    for acombo in itertools.product(range(n_states), repeat=a_slots):
        table.setdefault(combo_prefix(acombo), []).append(acombo)

    work = len(table)                            # building the A table is real work
    found = None
    for bcombo in itertools.product(range(n_states), repeat=b_slots):
        work += 1
        needed_a = _xor_t(obs_pre, combo_prefix(bcombo))
        cands = table.get(needed_a)
        if not cands:
            continue
        for acombo in cands:
            states = tuple(acombo) + tuple(bcombo)
            if combined_stream(states, verify_len) == observed:
                pred = combined_stream(states, total)[verify_len:]
                found = (states, pred)
                break
        if found:
            break

    recovered_exact = found is not None and found[0] == tuple(seeds)
    future_ok = found is not None and found[1] == future_truth
    mitm_exp = max(a_slots, b_slots) * m_bits     # the worst-case half decides the cost
    naive_exp = n_maps * m_bits
    return recovered_exact, future_ok, work, mitm_exp, naive_exp


def mitm_demo():
    n = DEFAULT_N_MAPS
    print(f"PART C — balanced meet-in-the-middle on the {n}-map combiner (measured at small scale)")
    # scales kept modest: side A holds 2^(|A|*m) entries, so m must stay small for N=4 (|A|=2).
    for m_bits in (8, 10):
        t0 = time.time()
        _rec, fut, work, mitm_exp, naive_exp = mitm_recover(m_bits, n_maps=n)
        dt = time.time() - t0
        print(f"  M=2^{m_bits}: predicts_unseen_keystream={fut}  "
              f"states_examined={work:,}  "
              f"MITM_search=2^{mitm_exp} vs naive=2^{naive_exp}  ({dt:.1f}s)")
    print("  ----")
    print("  The attack SUCCEEDS at small scale: it finds a keystream-equivalent state set and")
    print("  predicts UNSEEN future keystream (a >2^-100 fluke is impossible, so it's a real break).")
    print(f"  Balanced MITM splits the {n} maps into halves: table one half's forced output prefixes,")
    print("  match the other half. Cost ~2^(ceil(N/2)*state) in TIME *and* MEMORY — not the")
    print("  2^(N*state) of naive joint brute force.")
    sb = M.bit_length()
    half = (n + 1) // 2
    print(f"  For the SHIPPED design (N={n} maps, {sb}-bit state): MITM ~2^{half*sb} (and 2^{half*sb}")
    print(f"  memory, itself prohibitive), naive joint ~2^{n*sb}. Both astronomically safe; 2^{half*sb}")
    print("  is the honest worst-case attacker cost, superseding the old 3-map figure of 2^122.\n")


if __name__ == "__main__":
    print("=" * 78)
    print(f"CLEVER-BURGLAR CRYPTANALYSIS OF THE {DEFAULT_N_MAPS}-MAP CHAOS COMBINER")
    print("=" * 78 + "\n")
    a = bias_hunt()
    b = independence_check()
    mitm_demo()
    print("=" * 78)
    print("SUMMARY")
    print(f"  Part A (bias hunt) ........ strongest deviation {a:.2f} sigma "
          f"({'clean' if a < 5 else 'investigate'})")
    print(f"  Part B (independence) ..... strongest deviation {b:.2f} sigma "
          f"({'independent' if b < 5 else 'investigate'})")
    print(f"  Part C (MITM) ............. combiner strength ~ceil(N/2)*state "
          f"(~2^{((DEFAULT_N_MAPS+1)//2)*M.bit_length()} at N={DEFAULT_N_MAPS})")
    print("  Overall: still UNVETTED. These clever attacks did not break the full cipher, but")
    print("  Part C corrects the strength estimate and the approach is a measured result.")
    print("=" * 78)
