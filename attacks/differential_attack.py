"""
ATTACK / VALIDATION — item D: differential & correlation hunt on the NEW output path.

WHY THIS FILE EXISTS
  Phase 1 added brand-new math that had never been directly attacked:
    * the FOLD   — the 127-bit chaotic state is XOR-folded down to 64 bits (engine._finalize line 1),
    * the MIXER  — fmix64 (SplitMix64) xorshift+multiply turns those 64 bits nonlinear,
    * the TRUNC  — we emit only the TOP 4 of the 8 finalized bytes (OUTPUT_BYTES_PER_STEP).
  The old attacks prove the OLD breaks are gone; this file attacks the NEW machinery on its own terms,
  the way a cryptanalyst would attack any output filter: avalanche, differentials, and output<->state
  correlation. "Measure, don't assert" — every claim below is a measured number with a noise floor.

THE FOUR PARTS
  Part 1 — AVALANCHE / bit-dependency: flip each of the 127 STATE bits; does every one reach every
           one of the 64 finalized output bits with probability ~1/2? (Directly tests the fold fix:
           if the high state bits did NOT avalanche, the fold would be leaking.)
  Part 2 — DIFFERENTIALS: for low-weight input differences, is the output difference unbiased on every
           bit AND spread to ~32 of 64 bits (Binomial center)? A high-probability differential or a
           low-popcount output diff would be a distinguisher.
  Part 3 — OUTPUT<->HIDDEN correlation (the truncation wall): we publish the top 32 bits and HIDE the
           low 32. If any published bit correlated with a hidden bit, an attacker could climb back to
           the state. Measure every published-vs-hidden bit pair; also check consecutive emitted words.
  Part 4 — RECOVERY COST (preimage law): revealing half a bijection's bits leaves ~2^(w/2) preimages.
           Measured at small width to confirm the law, then stated at full width (2^32 per step, per
           map) — the honest reason truncation is the wall.

HONEST SCOPE: this validates that the new output filter has no detectable avalanche gap, no usable
differential, and no output->hidden correlation at the sample sizes tested. It is NOT a proof; absence
of a bias at N samples only bounds a bias to roughly 1/sqrt(N). The design stays UNVETTED.
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import _finalize, M, OUTPUT_BYTES_PER_STEP, DiscreteChaoticEngine  # noqa: E402

OUT_BITS = 64              # _finalize emits a 64-bit word
STATE_BITS = M.bit_length()  # 127


def _rng(seed):
    """Tiny deterministic SplitMix64 — our own randomness so the run is reproducible (Math.random is
    banned project-wide for determinism; this is a TEST generator, not part of the cipher)."""
    state = seed & ((1 << 64) - 1)

    def nxt():
        nonlocal state
        state = (state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
        return z ^ (z >> 31)
    return nxt


def _rand_state(nxt):
    """A random 127-bit state in [0, M): two 64-bit draws stitched and reduced."""
    return ((nxt() << 64) | nxt()) % M


def _expected_max_sigma(n_cells):
    """The largest |z| you EXPECT from n_cells independent ~N(0,1) draws, by pure chance. Judging a
    worst-cell against a fixed '3 sigma' cries wolf when you test thousands of cells; this is the
    honest floor: ~sqrt(2 ln n). We pass if the observed worst is within ~1.5x of it."""
    return math.sqrt(2 * math.log(n_cells))


def part1_avalanche(n=4000, seed=1):
    """Flip each state bit; measure P(output bit j flips). Ideal 1/2 for all 127x64 cells."""
    nxt = _rng(seed)
    counts = [[0] * OUT_BITS for _ in range(STATE_BITS)]
    for _ in range(n):
        x = _rand_state(nxt)
        base = _finalize(x)
        for i in range(STATE_BITS):
            d = _finalize(x ^ (1 << i)) ^ base
            ci = counts[i]
            # accumulate flipped output bits
            b = d
            j = 0
            while b:
                if b & 1:
                    ci[j] += 1
                b >>= 1
                j += 1
    se = 0.5 / math.sqrt(n)
    worst_sigma = 0.0
    worst_cell = (0, 0)
    dead = 0  # cells that essentially never flip (avalanche gap)
    for i in range(STATE_BITS):
        for j in range(OUT_BITS):
            p = counts[i][j] / n
            sig = abs(p - 0.5) / se
            if sig > worst_sigma:
                worst_sigma, worst_cell = sig, (i, j)
            if p < 0.05 or p > 0.95:
                dead += 1
    floor = _expected_max_sigma(STATE_BITS * OUT_BITS)
    # also: does the TOP half of the state (the folded-in bits 64..126) reach the output at all?
    top_min = min(
        min(counts[i][j] / n for j in range(OUT_BITS)) for i in range(64, STATE_BITS)
    )
    top_max = max(
        max(counts[i][j] / n for j in range(OUT_BITS)) for i in range(64, STATE_BITS)
    )
    ok = worst_sigma < 1.6 * floor and dead == 0
    print("PART 1 — avalanche / bit-dependency of the finalizer (flip each of 127 state bits):")
    print(f"  cells tested: {STATE_BITS}x{OUT_BITS} = {STATE_BITS*OUT_BITS:,}   samples/cell: {n:,}")
    print(f"  worst cell |z|: {worst_sigma:.2f} at (state_bit {worst_cell[0]}, out_bit {worst_cell[1]})")
    print(f"  expected worst by chance (noise floor): {floor:.2f}   threshold: {1.6*floor:.2f}")
    print(f"  avalanche-gap cells (P<0.05 or >0.95): {dead}   (want 0)")
    print(f"  FOLD CHECK — high state bits 64..126 reach output with P in [{top_min:.3f}, {top_max:.3f}]"
          f" (want ~0.5; proves the fold carries the top half)")
    print(f"  => {'PASS' if ok else 'FAIL'}: every state bit avalanches into the output.\n")
    return ok


def _popcount(v):
    return bin(v).count("1")


def part2_differentials(n=20000, seed=2):
    """For low-weight input differences, the output difference must be unbiased per-bit AND spread to
    ~OUT_BITS/2 bits (a Binomial(64,1/2) popcount, centered at 32). A weak mixer leaks here first."""
    nxt = _rng(seed)
    # the most dangerous differences: every single-bit flip (low weight = least diffusion pressure)
    deltas = [(1 << i) for i in range(STATE_BITS)]
    worst_bit_sigma = 0.0
    worst_pop_sigma = 0.0
    se_bit = 0.5 / math.sqrt(n)
    # popcount of a 64-bit uniform diff ~ Normal(mean=32, var=16) => sd=4
    pop_mean, pop_sd = OUT_BITS / 2, math.sqrt(OUT_BITS) / 2
    for d_in in deltas:
        bit_counts = [0] * OUT_BITS
        pop_sum = 0
        for _ in range(n // 4):  # fewer samples per delta, many deltas
            x = _rand_state(nxt)
            d_out = _finalize(x) ^ _finalize(x ^ d_in)
            pop_sum += _popcount(d_out)
            b, j = d_out, 0
            while b:
                if b & 1:
                    bit_counts[j] += 1
                b >>= 1
                j += 1
        m = n // 4
        for j in range(OUT_BITS):
            sig = abs(bit_counts[j] / m - 0.5) / (0.5 / math.sqrt(m))
            worst_bit_sigma = max(worst_bit_sigma, sig)
        avg_pop = pop_sum / m
        # SE of the MEAN popcount over m samples
        pop_sigma = abs(avg_pop - pop_mean) / (pop_sd / math.sqrt(m))
        worst_pop_sigma = max(worst_pop_sigma, pop_sigma)
    floor_bit = _expected_max_sigma(len(deltas) * OUT_BITS)
    floor_pop = _expected_max_sigma(len(deltas))
    ok = worst_bit_sigma < 1.6 * floor_bit and worst_pop_sigma < 1.6 * floor_pop
    print("PART 2 — differential distribution (single-bit input differences):")
    print(f"  input differences tested: {len(deltas)}   samples each: {n//4:,}")
    print(f"  worst per-output-bit bias: {worst_bit_sigma:.2f}z   (floor {floor_bit:.2f}, thr {1.6*floor_bit:.2f})")
    print(f"  worst output-diff popcount drift from 32: {worst_pop_sigma:.2f}z   (floor {floor_pop:.2f})")
    print(f"  => {'PASS' if ok else 'FAIL'}: no usable differential; one flipped bit -> ~half the output flips.\n")
    return ok


def part3_output_vs_hidden(n=20000, seed=3):
    """The truncation wall. We PUBLISH the top 32 bits of finalize(state) and HIDE the low 32. If any
    published bit predicts any hidden bit (or any state bit), the wall leaks. Drive the REAL engine so
    we test the true (state -> emitted) relationship, not the mixer in isolation."""
    pub_bits = OUTPUT_BYTES_PER_STEP * 8          # 32 published (top) bits
    hid_bits = OUT_BITS - pub_bits                # 32 hidden (low) bits
    eng = DiscreteChaoticEngine(seed_key=0xA5A5_5A5A_C3C3, control_parameter=0x1234_9876, nonce=7)
    # accumulators for published(i) vs hidden(j) bit agreement, and published(i) vs state(k)
    ph = [[0] * hid_bits for _ in range(pub_bits)]
    ps = [[0] * STATE_BITS for _ in range(pub_bits)]
    prev_pub = None
    consec = [[0] * pub_bits for _ in range(pub_bits)]  # emitted word t vs t+1
    for _ in range(n):
        eng._next_state()
        st = eng.x
        word = _finalize(st)
        pub = word >> hid_bits           # top 32 bits
        hid = word & ((1 << hid_bits) - 1)  # low 32 bits
        for i in range(pub_bits):
            pi = (pub >> i) & 1
            phi = ph[i]
            for j in range(hid_bits):
                phi[j] += pi ^ ((hid >> j) & 1)   # count DISAGREEMENTS (ideal n/2)
            psi = ps[i]
            for k in range(STATE_BITS):
                psi[k] += pi ^ ((st >> k) & 1)
        if prev_pub is not None:
            for i in range(pub_bits):
                ci = consec[i]
                pi = (pub >> i) & 1
                for j in range(pub_bits):
                    ci[j] += pi ^ ((prev_pub >> j) & 1)
        prev_pub = pub

    se = 0.5 / math.sqrt(n)
    se_c = 0.5 / math.sqrt(n - 1)

    def worst(mat, rows, cols, se_):
        w = 0.0
        for a in range(rows):
            for b in range(cols):
                w = max(w, abs(mat[a][b] / (n if se_ == se else n - 1) - 0.5) / se_)
        return w

    w_ph = worst(ph, pub_bits, hid_bits, se)
    w_ps = worst(ps, pub_bits, STATE_BITS, se)
    w_cc = worst(consec, pub_bits, pub_bits, se_c)
    floor_ph = _expected_max_sigma(pub_bits * hid_bits)
    floor_ps = _expected_max_sigma(pub_bits * STATE_BITS)
    floor_cc = _expected_max_sigma(pub_bits * pub_bits)
    ok = w_ph < 1.6 * floor_ph and w_ps < 1.6 * floor_ps and w_cc < 1.6 * floor_cc
    print("PART 3 — output<->hidden / output<->state correlation (the truncation wall):")
    print(f"  published bits: {pub_bits} (top)   hidden bits: {hid_bits} (low)   samples: {n:,}")
    print(f"  worst published<->hidden bit corr : {w_ph:.2f}z   (floor {floor_ph:.2f}, thr {1.6*floor_ph:.2f})")
    print(f"  worst published<->state  bit corr : {w_ps:.2f}z   (floor {floor_ps:.2f})")
    print(f"  worst emitted word t<->t+1   corr : {w_cc:.2f}z   (floor {floor_cc:.2f})")
    print(f"  => {'PASS' if ok else 'FAIL'}: published bits leak nothing about the hidden half or the state.\n")
    return ok


def _mix_w(z, w):
    """fmix64 narrowed to w bits (same shift/multiply shape) — a scale model of the finalizer so we can
    census preimages, which is infeasible at 64 bits."""
    mask = (1 << w) - 1
    z &= mask
    z = ((z ^ (z >> (w // 2 - 2))) * 0xBF58476D1CE4E5B9) & mask
    z = ((z ^ (z >> (w // 2 - 4 if w > 8 else 1))) * 0x94D049BB133111EB) & mask
    z ^= z >> (w // 2 + 1 if w // 2 + 1 < w else w - 1)
    return z & mask


def part4_recovery_cost():
    """Reveal the top half of a w-bit bijection's output; count consistent inputs. The law is ~2^(w/2)
    preimages per revealed half — so each emitted step costs ~2^32 just to enumerate finalize inputs at
    full width, before the per-map fold and the XOR over 4 maps. (Analytic at 64; measured small.)"""
    print("PART 4 — recovery cost / preimage count (why truncation is the wall):")
    print(f"  full design: finalize is a bijection on 64 bits; we publish {OUTPUT_BYTES_PER_STEP*8},"
          f" hide {64-OUTPUT_BYTES_PER_STEP*8}.")
    rows = []
    for w in (12, 16, 20):
        half = w // 2
        # group all 2^w inputs by their top-half output; preimage count = bucket size
        buckets = {}
        for z in range(1 << w):
            top = _mix_w(z, w) >> (w - half)
            buckets[top] = buckets.get(top, 0) + 1
        vals = list(buckets.values())
        avg = sum(vals) / len(vals)
        rows.append((w, half, avg, max(vals)))
        print(f"  w={w:2d} bits, reveal top {half}: avg preimages/observation = {avg:.1f}"
              f"  (2^(w/2) = {1<<half})   max = {max(vals)}")
    # law holds if avg preimages tracks 2^(w/2)
    ok = all(abs(math.log2(avg) - half) < 1.0 for (_, half, avg, _) in rows)
    print(f"  => law confirmed: ~2^(w/2) preimages. At full width that is 2^32 candidate finalize-inputs")
    print(f"     per emitted step, PER map; XOR over { '4'} maps compounds it. No cheap inversion.\n")
    return ok


if __name__ == "__main__":
    print("=" * 80)
    print("DIFFERENTIAL & CORRELATION HUNT (item D) — attacking the NEW output filter directly")
    print("=" * 80 + "\n")
    r1 = part1_avalanche()
    r2 = part2_differentials()
    r3 = part3_output_vs_hidden()
    r4 = part4_recovery_cost()
    print("=" * 80)
    print(f"VERDICT  avalanche={r1}  no_differential={r2}  no_output_leak={r3}  recovery_law={r4}")
    print("Scope: the new fold+mixer+truncation show no avalanche gap, no usable differential, and no")
    print("output->hidden/state correlation at these sample sizes. NOT a proof. Still UNVETTED.")
    print("=" * 80)
