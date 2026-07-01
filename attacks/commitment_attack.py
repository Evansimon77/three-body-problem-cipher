"""
ATTACK / VALIDATION — key-commitment (#6). Measure the property, don't assert it.

THE PROPERTY WE CLAIM
  The AEAD is KEY-COMMITTING: it is infeasible to produce a single blob that opens cleanly under
  two DIFFERENT keys. This is the guarantee AES-GCM and ChaCha20-Poly1305 famously LACK — for those,
  an attacker can build one ciphertext that decrypts to "pay $10" under Alice's key and "pay $10,000"
  under Bob's key, both passing the tag. Our shells add an explicit commitment (commit.py) to close it.

THE THREE PARTS
  Part 1 — Functional: a blob sealed under K1 is rejected under a batch of other keys (the commitment
           is what rejects it). Confirms the door is actually locked, for both aead.py and siv.py.
  Part 2 — The committing property, MEASURED: a cross-key forgery needs two keys with the SAME
           commitment for a fixed (salt, aad) — an HMAC-SHA256 collision. We run a birthday search at
           REDUCED commitment widths w, measure the work to first collision, and fit the exponent. If
           it tracks 2^(w/2), the full 256-bit commitment costs ~2^128 — infeasible. (Same measured-law
           style as differential_attack.py's preimage census.)
  Part 3 — Honest framing: why ours commits (HMAC, a committing MAC) and what the explicit field adds.

HONEST SCOPE: this validates the commitment construction (collision resistance of HMAC-SHA256 in the
key). It is NOT a proof that the chaos keystream is secure — that stays UNVETTED. Key-commitment is a
property of the SHELL, and the shell rides vetted HMAC-SHA256, so this part stands on solid ground.
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aead import InvalidTag, open_ as aead_open  # noqa: E402
from aead import seal as aead_seal  # noqa: E402
from commit import key_commitment  # noqa: E402
from siv import open_siv, seal_siv  # noqa: E402

_BAD = InvalidTag

MSG = b"send 100 to account #12345"


def part1_functional() -> bool:
    """A blob sealed under K1 must not open under any other key — for both shells."""
    k1 = b"the-one-true-master-key"
    others = [k1[:-1] + b"X", b"\x00" * len(k1), k1 + b"!", os.urandom(24), b"almost" + k1]

    aead_blob = aead_seal(k1, MSG, aad=b"ctx")
    siv_blob = seal_siv(k1, MSG, aad=b"ctx")

    aead_rejected = siv_rejected = 0
    for k2 in others:
        try:
            aead_open(k2, aead_blob, aad=b"ctx")
        except _BAD:
            aead_rejected += 1
        try:
            open_siv(k2, siv_blob, aad=b"ctx")
        except _BAD:
            siv_rejected += 1

    ok = aead_rejected == len(others) and siv_rejected == len(others)
    # And the legitimate key still opens both (no false reject).
    ok = ok and aead_open(k1, aead_blob, aad=b"ctx") == MSG
    ok = ok and open_siv(k1, siv_blob, aad=b"ctx") == MSG
    print(f"  Part 1  functional: aead rejected {aead_rejected}/{len(others)} foreign keys, "
          f"siv rejected {siv_rejected}/{len(others)}; legit key still opens both -> "
          f"{'PASS' if ok else 'FAIL'}")
    return ok


def _commit_w(key: bytes, w: int, salt: bytes, aad: bytes) -> int:
    """The top `w` bits of the real commitment for a fixed (salt, aad) — the forger's target."""
    c = key_commitment(key, salt, aad)
    return int.from_bytes(c, "big") >> (256 - w)


def _birthday_trials_to_collision(w: int, salt: bytes, aad: bytes, cap: int) -> int | None:
    """Draw random keys until two DISTINCT keys share their w-bit commitment. Returns the number of
    keys drawn, or None if `cap` is hit first (shouldn't happen for the small w we test)."""
    seen: dict[int, bytes] = {}
    for trials in range(1, cap + 1):
        key = os.urandom(16)
        h = _commit_w(key, w, salt, aad)
        prev = seen.get(h)
        if prev is not None and prev != key:
            return trials
        seen[h] = key
    return None


def part2_collision_law(widths=(12, 16, 20, 24), repeats=5) -> bool:
    """Measure work-to-first-collision vs commitment width; fit the exponent (expect ~0.5)."""
    salt, aad = b"\xa5" * 16, b"fixed-aad"
    xs, ys = [], []
    print("  Part 2  cross-key collision search (birthday) — a forgery needs two keys, same commit:")
    for w in widths:
        samples = []
        for _ in range(repeats):
            t = _birthday_trials_to_collision(w, salt, aad, cap=200 * (1 << (w // 2)))
            if t is None:
                print(f"    w={w:2d} bits: no collision within cap  <-- unexpected")
                return False
            samples.append(t)
        avg = sum(samples) / len(samples)
        xs.append(w)
        ys.append(math.log2(avg))
        print(f"    w={w:2d} bits: ~{avg:8.1f} keys to first collision "
              f"(birthday predicts ~{1.2533 * 2 ** (w / 2):8.1f})")

    # Least-squares slope of log2(trials) vs w. Birthday law => slope ~0.5.
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    full = 256 / 2  # full 256-bit commitment => 2^128 birthday cost
    ok = 0.42 <= slope <= 0.58
    print(f"    fitted exponent = {slope:.3f} (birthday law = 0.500) -> "
          f"{'tracks 2^(w/2)' if ok else 'OFF — investigate'}")
    print(f"    => full 256-bit commitment costs ~2^{full:.0f} to forge a cross-key collision: "
          f"infeasible. {'PASS' if ok else 'FAIL'}")
    return ok


def part3_honest_framing() -> bool:
    """Not a test — the honest 'why' so the number above isn't a black box."""
    print("  Part 3  honest framing:")
    print("    - Our tag/SIV use HMAC-SHA256, a COMMITTING MAC, so we largely avoided the GCM/Poly1305")
    print("      key-confusion attack already. The explicit commitment (commit.py) makes it provable")
    print("      and independent of MAC-key-derivation subtleties: CMT-4, binding key + salt + aad.")
    print("    - The keystream is still UNVETTED; key-commitment is a SHELL property on vetted HMAC.")
    return True


def main() -> None:
    print("=" * 78)
    print("KEY-COMMITMENT (#6) — validation")
    print("=" * 78)
    p1 = part1_functional()
    p2 = part2_collision_law()
    p3 = part3_honest_framing()
    print("-" * 78)
    verdict = "ALL PASS" if (p1 and p2 and p3) else "FAILURE — see above"
    print(f"VERDICT: {verdict}")
    sys.exit(0 if (p1 and p2 and p3) else 1)


if __name__ == "__main__":
    main()
