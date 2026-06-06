"""
ATTACK 2 — Known-plaintext / state-recovery.

The original claim under test: "A miss looks as random as any other; there is no structure
to exploit, so brute force is the ONLY option, and that outlasts the universe."

Reality check, in two parts:

PART A — Structure EXISTS (the map is invertible).
  Each branch of the PWLCM is an affine map x -> (M*(x-a))//d. That is *linear*, hence
  *invertible* up to the integer-division remainder: given an output state and the branch,
  the pre-image is a tiny interval. So there is plenty of algebraic structure — the "no
  clues" framing is wrong. What protects the cipher is not "no structure", it's the SIZE
  of the hidden state and unknown parameter.

PART B — A REAL state-recovery break, demonstrated at reduced scale.
  In a known-plaintext setting the attacker gets keystream bytes K_i = P_i ^ C_i, i.e. the
  top 8 bits of each successive state. Guess the hidden low/high bits of the FIRST state,
  roll the (deterministic) map forward, and keep only guesses whose predicted bytes match
  the observed ones. The true state is the unique survivor — after which ALL future
  keystream is predictable (full break, no key needed).

  Cost ~ 2^(state_bits - 8) (times the keyspace of p if p is also secret). We run it on a
  small-modulus clone to show it genuinely works, then extrapolate the work factor to the
  real engine honestly.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import M, DiscreteChaoticEngine  # noqa: E402


# ---------- PART A: show the real map is invertible (structure exists) ----------
def invert_step(x_next, p):
    """Given a successor state and p, return candidate predecessors (one per branch).
    Demonstrates the map carries exploitable affine structure."""
    HALF = M // 2
    cands = []
    # branch 1: x_next = M*x//p,  x in (0,p)        -> x ~= x_next*p//M
    x = (x_next * p) // M
    if 0 < x < p:
        cands.append(x)
    # branch 2: x_next = M*(x-p)//(HALF-p), x in [p,HALF)
    x = (x_next * (HALF - p)) // M + p
    if p <= x < HALF:
        cands.append(x)
    # branch 3: x_next = M*(M-p-x)//(HALF-p), x in [HALF, M-p)
    x = (M - p) - (x_next * (HALF - p)) // M
    if HALF <= x < (M - p):
        cands.append(x)
    # branch 4: x_next = M*(M-x)//p, x in [M-p, M)
    x = M - (x_next * p) // M
    if (M - p) <= x < M:
        cands.append(x)
    return cands


def demo_invertibility():
    eng = DiscreteChaoticEngine(424242424242, 191919191919, nonce=5)
    x0 = eng.x
    eng._next_state()
    x1 = eng.x
    preimages = invert_step(x1, eng.p)
    near = min((abs(c - x0) for c in preimages), default=None)
    print("PART A — invertibility of the real map:")
    print(f"  true predecessor x0 = {x0}")
    print(f"  recovered candidates = {preimages}")
    print(f"  closest candidate is off by {near} (small => map is affine/invertible)")
    print("  => There IS structure. 'No clues at all' is false.\n")


# ---------- PART B: a working state-recovery on a small-modulus clone ----------
class SmallPWLCM:
    """Same shape as the real engine but with a tunable, small modulus, so a real
    state-recovery attack runs in seconds and we can MEASURE its cost."""

    def __init__(self, m_bits, x0, p, out_bits=8):
        self.M = (1 << m_bits) - 1
        self.HALF = self.M // 2
        self.shift = m_bits - out_bits          # take the top out_bits as the keystream byte
        self.mask = (1 << out_bits) - 1
        self.p = p % self.HALF or 1
        self.x = x0 % self.M or 0x55

    def step(self):
        x, p, M_, HALF = self.x, self.p, self.M, self.HALF
        if 0 < x < p:
            x = (M_ * x) // p
        elif p <= x < HALF:
            x = (M_ * (x - p)) // (HALF - p)
        elif HALF <= x < (M_ - p):
            x = (M_ * (M_ - p - x)) // (HALF - p)
        elif (M_ - p) <= x < M_:
            x = (M_ * (M_ - x)) // p
        else:
            x = 0x55
        self.x = x

    def out(self):
        self.step()
        return (self.x >> self.shift) & self.mask

    def stream(self, n):
        return [self.out() for _ in range(n)]


def recover_state(m_bits, p, observed, predict_extra=8):
    """Brute-force the hidden bits of the first state; survivor predicts the future.
    Assumes p known (worst case for the attacker = only the seed is secret).

    `observed[0]` fixes the top 8 bits of the searched state; the remaining
    `observed[1:]` (we use up to 11 bytes = 88 bits of constraint) uniquely pin it,
    so false-positive collisions are driven to ~2^-88."""
    M_ = (1 << m_bits) - 1
    shift = m_bits - 8
    first_byte = observed[0]
    lo = first_byte << shift
    hi = lo + (1 << shift)            # candidate range consistent with the first output byte
    checks = observed[1:12]           # 11 bytes => unique state, no false positives
    tested = 0
    for x0 in range(lo, min(hi, M_)):
        tested += 1
        clone = SmallPWLCM(m_bits, x0, p)
        clone.x = x0
        if all(clone.out() == b for b in checks):
            # confirmed — predict beyond what we observed
            predicted = [clone.out() for _ in range(predict_extra)]
            return x0, tested, predicted
    return None, tested, None


def demo_state_recovery():
    print("PART B — real state-recovery on a small-modulus clone:")
    for m_bits in (20, 24):
        p = (1 << (m_bits - 2)) - 17
        true_x0 = (123456789 ^ (p * 7)) % ((1 << m_bits) - 1) or 0x55
        truth = SmallPWLCM(m_bits, true_x0, p)
        truth.x = true_x0
        observed = truth.stream(12)             # attacker's known-plaintext window
        future_truth = truth.stream(8)          # the bytes the attacker must NOT have seen

        t0 = time.time()
        x0, tested, predicted = recover_state(m_bits, p, observed)
        dt = time.time() - t0
        ok = predicted == future_truth
        print(f"  M=2^{m_bits}: recovered={x0 is not None}  candidates_tried={tested:,} "
              f"({dt:.2f}s)  future-bytes-correctly-predicted={ok}")
    print("  => At small scale the cipher is fully broken with known plaintext.\n")


def extrapolate():
    state_bits = M.bit_length()              # 61
    print("Honest extrapolation to the REAL engine:")
    print(f"  state size      : ~{state_bits} bits  (M = 2^61 - 1)")
    print(f"  naive recovery  : ~2^{state_bits - 8} ops with p known "
          f"(times ~2^60 if p is secret)")
    print("  => This naive known-plaintext attack does NOT break the full engine: the")
    print("     work factor is astronomical. BUT note WHY it's safe — it's a *key-size*")
    print("     argument (big hidden state + secret p), exactly like a normal cipher.")
    print("     It is NOT the claimed 'no structure / no possible attack'. Structure")
    print("     exists (Part A); smarter algebraic attacks on PWLCM ciphers are an active")
    print("     research area and several published variants HAVE been broken. Unvetted.")


if __name__ == "__main__":
    demo_invertibility()
    demo_state_recovery()
    extrapolate()
