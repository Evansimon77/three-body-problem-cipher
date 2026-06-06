"""
Chaos-based stream cipher engine — RESEARCH ARTIFACT, NOT PRODUCTION CRYPTO.

This implements the user's proposed design faithfully: a discretized, pure-integer
Piecewise Linear Chaotic Map (PWLCM) used as a keystream generator, XOR'd with the
plaintext. Pure-integer math (modulus M = 2**61 - 1, a Mersenne prime) makes the
keystream bit-for-bit identical on any CPU/OS — this solves the "finite precision
paradox" that kills floating-point chaos ciphers.

WHAT IS FAITHFUL TO THE ORIGINAL PROPOSAL:
  - PWLCM core map, integer-only.
  - Byte extraction via (state >> 24) & 0xFF.
  - XOR keystream encryption (encrypt == decrypt).

WHAT WAS ADDED so the design can be *fairly tested* (and used without an instant break):
  - A nonce/IV. Keystream = f(key, nonce). Without this, encrypting two messages with
    the same key is a two-time pad — an instant break that has nothing to do with the
    map's quality. attacks/two_time_pad.py deliberately demonstrates that footgun.

SECURITY STATUS: UNVETTED. This is a homemade cipher built to be *attacked and measured*,
not trusted. Do not protect real data with it. See REPORT.md for the empirical verdict.
"""

from __future__ import annotations

# Mersenne prime modulus — the size of the integer "grid" the chaotic state lives on.
M = (1 << 61) - 1          # 2305843009213693951
HALF = M // 2
DEAD_STATE_FIX = 0x5555555555555555 % M  # escape value if the map hits the 0 fixed point


class DiscreteChaoticEngine:
    """Integer PWLCM keystream generator + XOR stream cipher.

    Parameters
    ----------
    seed_key : int
        The secret. Sets the initial chaotic state x0. (>= 122 bits recommended.)
    control_parameter : int
        The map's break-point p (akin to a gravitational constant). Part of the secret.
    nonce : int
        Public, per-message. Must be unique per (key) to avoid keystream reuse.
        Mixed into the initial state so the same key yields a fresh keystream each message.
    """

    # Smallest break-point we allow. p in {0, 1} (and the symmetric top end) put almost
    # the entire state into one branch and collapse the orbit — the period-1 weak class
    # found in adversarial testing. We reject that whole neighbourhood.
    MIN_P = 1 << 40

    def __init__(self, seed_key: int, control_parameter: int, nonce: int = 0):
        # --- derive the break-point p, with weak-parameter REJECTION ---
        # p must sit well inside (0, HALF): not tiny, not within MIN_P of HALF.
        self.p = control_parameter % HALF
        if not (self.MIN_P <= self.p <= HALF - self.MIN_P):
            # Map degenerate / weak parameters into the safe middle band instead of
            # collapsing. Deterministic, so sync is preserved.
            self.p = self.MIN_P + (self.p % (HALF - 2 * self.MIN_P))

        # --- derive initial state x from key, then fold the nonce in ---
        # Nonce mixing: a couple of integer-mix rounds so distinct nonces land in
        # very different regions of the state space. Still 100% deterministic.
        x = seed_key % M
        n = nonce % M
        x = (x ^ ((n * 0x9E3779B97F4A7C15) % M)) % M     # golden-ratio odd multiplier mix
        x = (x + ((n << 17) % M) + 1) % M
        if x == 0:
            x = DEAD_STATE_FIX
        self.x = x

        # Warm-up: discard initial outputs so the keystream doesn't expose the raw
        # key/nonce-derived state in its first bytes.
        for _ in range(16):
            self._next_state()

    @classmethod
    def from_master(cls, master_key: bytes, nonce: bytes) -> "DiscreteChaoticEngine":
        """Build an engine from arbitrary byte-string material via a hash-based KDF.

        Any master_key + nonce maps to a well-distributed seed_key and control_parameter,
        so a caller can NEVER accidentally pick a weak key — the hash output is uniform and
        the weak-parameter band is rejected in __init__ anyway. This is how the AEAD layer
        (aead.py) seeds the keystream. Deterministic => Alice and Bob still sync."""
        import hashlib

        h = hashlib.sha512(b"chaos-pwlcm-v1|seed|" + master_key + b"|" + nonce).digest()
        seed_key = int.from_bytes(h[0:24], "big")      # 192 bits of state seed
        control = int.from_bytes(h[24:48], "big")      # 192 bits -> mapped into safe band
        return cls(seed_key, control, nonce=0)         # nonce already mixed into the hash

    def _next_state(self) -> None:
        """One step of the integer PWLCM. Pure integer math => identical on all CPUs."""
        x, p = self.x, self.p
        if 0 < x < p:
            x = (M * x) // p
        elif p <= x < HALF:
            x = (M * (x - p)) // (HALF - p)
        elif HALF <= x < (M - p):
            x = (M * (M - p - x)) // (HALF - p)
        elif (M - p) <= x < M:
            x = (M * (M - x)) // p
        else:
            x = DEAD_STATE_FIX  # x == 0 (or out of range): escape the dead fixed point
        self.x = x

    def generate_byte(self) -> int:
        """Advance one step and emit 8 bits from the middle of the 61-bit state."""
        self._next_state()
        return (self.x >> 24) & 0xFF

    def keystream(self, n: int) -> bytes:
        """Return the next n keystream bytes."""
        return bytes(self.generate_byte() for _ in range(n))

    def encrypt(self, data: bytes) -> bytes:
        """XOR data with the keystream. Running the SAME engine state over the output
        decrypts. (Stateful: advances the keystream — make a fresh engine to decrypt.)"""
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ self.generate_byte()
        return bytes(out)

    # decrypt is identical to encrypt for an XOR stream cipher
    decrypt = encrypt


def cipher(seed_key: int, control_parameter: int, nonce: int = 0) -> DiscreteChaoticEngine:
    """Convenience factory."""
    return DiscreteChaoticEngine(seed_key, control_parameter, nonce)
