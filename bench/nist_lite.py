"""
Pure-Python NIST-subset randomness tests (zero external deps).

Implements three of the NIST SP 800-22 tests that catch the most common keystream flaws:
  1. Monobit (frequency)      — are there ~equal 0s and 1s?
  2. Runs                     — too many / too few bit-runs?
  3. Block frequency          — are 0/1 balanced within blocks?

Each returns a p-value; p >= 0.01 = pass (cannot distinguish from random by this test).
This is a screen, not a proof — `bench/randomness.sh` adds ent/dieharder when available.
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine  # noqa: E402


def _bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def erfc(x):  # complementary error function
    return math.erfc(x)


def monobit(data):
    n = len(data) * 8
    s = sum(1 if b else -1 for b in _bits(data))
    return erfc(abs(s) / math.sqrt(2 * n))


def runs(data):
    bits = list(_bits(data))
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return 0.0  # fails prerequisite
    vobs = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])
    num = abs(vobs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    return erfc(num / den)


def block_frequency(data, block=128):
    bits = list(_bits(data))
    n = len(bits)
    nblocks = n // block
    if nblocks == 0:
        return 1.0
    chi = 0.0
    for i in range(nblocks):
        ones = sum(bits[i * block:(i + 1) * block])
        pi = ones / block
        chi += (pi - 0.5) ** 2
    chi *= 4 * block
    # p-value via upper incomplete gamma (igamc) with df = nblocks
    return _igamc(nblocks / 2.0, chi / 2.0)


def _igamc(a, x):
    """Regularized upper incomplete gamma Q(a,x), continued-fraction / series."""
    if x <= 0:
        return 1.0
    if x < a + 1:  # series for lower, then complement
        ap, summ, term = a, 1.0 / a, 1.0 / a
        for _ in range(1000):
            ap += 1
            term *= x / ap
            summ += term
            if abs(term) < abs(summ) * 1e-15:
                break
        return 1.0 - summ * math.exp(-x + a * math.log(x) - math.lgamma(a))
    # continued fraction for upper
    b = x + 1 - a
    c = 1e300
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        if abs(d) < 1e-300:
            d = 1e-300
        c = b + an / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delt = d * c
        h *= delt
        if abs(delt - 1.0) < 1e-15:
            break
    return h * math.exp(-x + a * math.log(x) - math.lgamma(a))


def run(nbytes=200_000):
    ks = DiscreteChaoticEngine(0xCAFEBABEDEADBEEF1234, 0x9999999999999, nonce=7).keystream(nbytes)
    results = {
        "monobit": monobit(ks),
        "runs": runs(ks),
        "block_frequency(128)": block_frequency(ks),
    }
    print(f"NIST-lite on {nbytes:,} keystream bytes ({nbytes*8:,} bits):\n")
    for name, p in results.items():
        print(f"  {name:22s}: p={p:.4f}  -> {'PASS' if p >= 0.01 else 'FAIL'}")
    # byte histogram chi-square (uniformity of byte values)
    hist = [0] * 256
    for b in ks:
        hist[b] += 1
    exp = nbytes / 256
    chi = sum((h - exp) ** 2 / exp for h in hist)
    print(f"\n  byte chi-square (df=255): {chi:.1f}  (ideal ~255; >330 or <180 is suspect)")
    return results


if __name__ == "__main__":
    run()
