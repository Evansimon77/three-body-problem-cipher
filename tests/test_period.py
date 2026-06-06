"""
THE most important test for any discretized chaotic map.

A continuous chaotic system is non-periodic. Its INTEGER approximation lives on a finite
set of states, so by the pigeonhole principle it MUST eventually cycle. If that cycle is
short, the keystream repeats -> the cipher is catastrophically broken (repeating keystream
= many-time pad).

We use Brent's cycle-detection algorithm on the raw 61-bit state (not the output byte),
which finds the period (lambda) and the tail length (mu) without storing the whole orbit.

Run directly to print a measurement, or via pytest for a sanity threshold.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine  # noqa: E402


def _advance(eng):
    eng._next_state()
    return eng.x


def brent_period(seed_key, ctrl, nonce, max_steps=5_000_000):
    """Brent's algorithm. Returns (lam, mu) or (None, None) if no cycle within max_steps."""
    def fresh():
        return DiscreteChaoticEngine(seed_key, ctrl, nonce)

    # find lambda (cycle length)
    power = lam = 1
    tortoise = fresh()
    t_val = tortoise.x
    hare = fresh()
    h_val = _advance(hare)
    steps = 0
    while t_val != h_val:
        if power == lam:
            t_val = h_val
            power *= 2
            lam = 0
        h_val = _advance(hare)
        lam += 1
        steps += 1
        if steps > max_steps:
            return None, None

    # find mu (tail length before entering the cycle)
    tortoise = fresh()
    hare = fresh()
    t_val = tortoise.x
    h_val = hare.x
    for _ in range(lam):
        h_val = _advance(hare)
    mu = 0
    while t_val != h_val:
        t_val = _advance(tortoise)
        h_val = _advance(hare)
        mu += 1
        if mu > max_steps:
            return lam, None
    return lam, mu


def measure(label, key, ctrl, nonce, max_steps=2_000_000):
    lam, mu = brent_period(key, ctrl, nonce, max_steps)
    if lam is None:
        print(f"  {label:18s}: period > {max_steps:,} (no cycle found in budget) — GOOD")
    else:
        verdict = "FATAL" if lam < 1_000_000 else "concerning" if lam < 100_000_000 else "ok-ish"
        print(f"  {label:18s}: period(lambda)={lam:,}  tail(mu)={mu}  -> {verdict}")
    return lam


def test_period_not_trivially_short():
    # A short cycle within a tiny budget would be an immediate disqualifier.
    lam, _ = brent_period(987654321012345987654321, 333333333333333222111, 42,
                          max_steps=500_000)
    assert lam is None or lam > 4096, f"Keystream cycles after only {lam} states — broken"


if __name__ == "__main__":
    print("Period / cycle detection (Brent's algorithm) on the 61-bit state:\n")
    measure("default key", 987654321012345987654321, 333333333333333222111, 42)
    measure("small key/ctrl", 12345, 67891, 1)
    measure("key=1 ctrl=1", 1, 1, 0)
    measure("alt nonce", 987654321012345987654321, 333333333333333222111, 99999)
    print("\nNote: integer maps ALWAYS cycle eventually. The question is whether the")
    print("period is astronomically large (safe) or reachable (broken). See REPORT.md.")
