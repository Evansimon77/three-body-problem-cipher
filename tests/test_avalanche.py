"""
Avalanche / key sensitivity — quantifies the "butterfly effect" claim with a number
instead of an assertion.

Flip ONE bit of the key (then the nonce), regenerate the keystream, and measure what
fraction of output bits changed. For a good cipher this is ~50% (each input bit affects
each output bit with probability 1/2). Far from 50% => structure an attacker can use.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine  # noqa: E402

KEY = 0xA5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5
CTRL = 0x3333333333333333333333333333
NONCE = 0x0123456789ABCDEF
NBYTES = 4096


def _bit_diff_fraction(a: bytes, b: bytes) -> float:
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return diff / (len(a) * 8)


def avalanche_over_key_bits(n_trials=64, key_bits=128):
    base = DiscreteChaoticEngine(KEY, CTRL, NONCE).keystream(NBYTES)
    fractions = []
    for i in range(min(n_trials, key_bits)):
        flipped = DiscreteChaoticEngine(KEY ^ (1 << i), CTRL, NONCE).keystream(NBYTES)
        fractions.append(_bit_diff_fraction(base, flipped))
    return fractions


def avalanche_over_nonce_bits(n_trials=64):
    base = DiscreteChaoticEngine(KEY, CTRL, NONCE).keystream(NBYTES)
    fractions = []
    for i in range(n_trials):
        flipped = DiscreteChaoticEngine(KEY, CTRL, NONCE ^ (1 << i)).keystream(NBYTES)
        fractions.append(_bit_diff_fraction(base, flipped))
    return fractions


def test_key_avalanche_near_half():
    fr = avalanche_over_key_bits()
    avg = sum(fr) / len(fr)
    assert 0.45 <= avg <= 0.55, f"Key avalanche {avg:.4f} too far from ideal 0.5"


def test_nonce_avalanche_near_half():
    fr = avalanche_over_nonce_bits()
    avg = sum(fr) / len(fr)
    assert 0.45 <= avg <= 0.55, f"Nonce avalanche {avg:.4f} too far from ideal 0.5"


if __name__ == "__main__":
    kf = avalanche_over_key_bits()
    nf = avalanche_over_nonce_bits()
    ka = sum(kf) / len(kf)
    na = sum(nf) / len(nf)
    print("Avalanche (ideal = 0.5000, i.e. ~50% of output bits flip):\n")
    print(f"  key-bit flips   : mean={ka:.4f}  min={min(kf):.4f}  max={max(kf):.4f}")
    print(f"  nonce-bit flips : mean={na:.4f}  min={min(nf):.4f}  max={max(nf):.4f}")
