"""
Timing-leak measurement (constant-time spec, Phase 3) — MEASURE, don't assert.

The code claims two things about the PWLCM step's timing:
  (1) The BRANCH leak is CLOSED. The old 4-way if/elif chose a segment by the secret state, so
      different states could take different time. The branchless rewrite evaluates all four
      candidates every step => step time should NOT depend on which region the state is in.
  (2) A DIVISION leak REMAINS. The step still divides by the secret-derived p and (HALF - p).
      On real hardware integer division latency is data-dependent, so this is a timing channel
      the branch-removal does NOT close — the reason the Rust core must use a precomputed
      reciprocal (Barrett/Montgomery) instead of `// p`.

This script measures BOTH at the Python level and reports honestly, including the limitation
that CPython's interpreter overhead largely MASKS the divide signal (so the leak is a hardware
/ Rust-port concern, not a Python-exploitable one). That honesty is the point: we report what
the numbers actually show, not what we wish they showed.

    python3 bench/timing_leak.py [trials]
"""

from __future__ import annotations

import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import HALF, M, DiscreteChaoticEngine  # noqa: E402


def _time_steps(eng: DiscreteChaoticEngine, n: int) -> float:
    """Median per-step time (seconds) over n PWLCM steps, taking the min of repeats to
    suppress scheduler noise."""
    best = float("inf")
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(n):
            eng._next_state()
        dt = (time.perf_counter() - t0) / n
        best = min(best, dt)
    return best


def measure_region_independence(n: int) -> None:
    """(1) Branch leak: force the state into each PWLCM region and time the step. Constant-time
    means the four region timings agree within noise."""
    print("\n(1) BRANCH leak — step time by which region the state sits in")
    print("    (branchless => these should be ~equal; a spread would mean a residual branch)")
    eng = DiscreteChaoticEngine(12345, 67890, nonce=1)
    p = eng.p
    # One representative state per region; we re-pin eng.x before each timed run so the timed
    # work starts from that region. (The state moves as it iterates; this measures the entry mix
    # of regions a long run visits, which is what an attacker would average over anyway.)
    region_states = {
        "(0, p)        ": p // 2,
        "[p, HALF)     ": p + (HALF - p) // 2,
        "[HALF, M-p)   ": HALF + (M - p - HALF) // 2,
        "[M-p, M)      ": (M - p) + (p // 2),
    }
    times = {}
    for label, x0 in region_states.items():
        eng.x = x0
        t = _time_steps(eng, n)
        times[label] = t
        print(f"    region {label}: {t * 1e9:8.1f} ns/step")
    spread = (max(times.values()) - min(times.values())) / statistics.mean(times.values())
    print(f"    -> spread across regions: {spread * 100:.1f}% "
          f"({'within noise — branch leak closed' if spread < 0.15 else 'NOTABLE — investigate'})")


def measure_divisor_dependence(n: int) -> None:
    """(2) Division leak: vary the SECRET divisor p across its legal band and time the step.
    A systematic trend = the divide timing depends on the secret (the leak the Rust reciprocal
    must remove). At the Python level this is expected to be buried under interpreter noise."""
    print("\n(2) DIVISION leak — step time vs the secret divisor p")
    print("    (a clean trend = secret-dependent divide; Python overhead is expected to mask it)")
    fracs = [0.001, 0.01, 0.1, 0.25, 0.5, 0.75, 0.99]
    times = []
    for fr in fracs:
        # Build an engine whose p lands near this fraction of HALF. control_parameter % HALF == p
        # for values already inside the safe band, so we pass the target directly.
        target = max(DiscreteChaoticEngine.MIN_P,
                     min(HALF - DiscreteChaoticEngine.MIN_P, int(fr * HALF)))
        eng = DiscreteChaoticEngine(0xABCDEF, target, nonce=7)
        t = _time_steps(eng, n)
        times.append(t)
        print(f"    p ~= {fr:5.3f}*HALF  ({eng.p.bit_length():3d} bits): {t * 1e9:8.1f} ns/step")
    spread = (max(times) - min(times)) / statistics.mean(times)
    print(f"    -> spread across divisors: {spread * 100:.1f}%")
    if spread < 0.15:
        print("    -> VERDICT: no clean Python-level signal — interpreter overhead masks the divide.")
        print("       The leak is a HARDWARE/Rust-port concern: native `// p` exposes data-dependent")
        print("       divide latency. Fix = precomputed reciprocal (Barrett/Montgomery) at key setup.")
    else:
        print("    -> VERDICT: measurable divisor-dependent timing — confirms the leak directly.")


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    print(f"Timing-leak measurement — {n} steps per sample, min-of-5 repeats")
    print(f"M = 2^127-1, HALF = {HALF.bit_length()} bits")
    measure_region_independence(n)
    measure_divisor_dependence(n)


if __name__ == "__main__":
    main()
