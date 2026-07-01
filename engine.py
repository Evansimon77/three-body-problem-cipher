"""
Chaos-based stream cipher engine — RESEARCH ARTIFACT, NOT PRODUCTION CRYPTO.

This implements the user's proposed design faithfully: a discretized, pure-integer
Piecewise Linear Chaotic Map (PWLCM) used as a keystream generator, XOR'd with the
plaintext. Pure-integer math (modulus M = 2**127 - 1, the Mersenne prime M127) makes the
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
# Mersenne prime M127 — the integer "grid" the chaotic state lives on (#1, the bigger grid).
# Moving from 2^61-1 to 2^127-1 raises the per-map orbit length: by the random-function rho law
# the period scales as ~sqrt(M), so this lifts the honest per-map period from ~2^30 to ~2^63.
# (Verify the rho law at small scale with attacks/period_census.py; the 2^63 figure is the law's
# PREDICTION at the new M, not a direct measurement — 2^63 is too large to census.)
M = (1 << 127) - 1         # 170141183460469231731687303715884105727  (Mersenne prime M127)
HALF = M // 2
# Mid-space escape if the map ever hits the 0 fixed point. 128-bit alternating pattern % M lands
# well inside (0, M) for any grid up to 2^128, so this scales with M automatically.
DEAD_STATE_FIX = 0x55555555555555555555555555555555 % M

MASK64 = (1 << 64) - 1

# --- Output hardening (#3 "frosted glass") + throughput (#4) -----------------------------------
# We do NOT emit the raw state. Each chaotic step's state is run through a nonlinear finalizer
# (finalize) and we emit OUTPUT_BYTES_PER_STEP bytes of the result. This knob trades speed vs
# security:
#   * SECURITY: the finalizer (xorshift + multiply, "ARX") destroys the PWLCM's piecewise-LINEAR
#     structure, so an attacker can't algebraically roll the output back to the state — closing the
#     invertibility weakness the old raw "(x >> 24) & 0xFF" left open. We also emit FEWER bytes than
#     the finalized word is wide, so part of every state stays hidden behind the glass.
#   * SPEED: more bytes per expensive step => fewer steps per message (the #4 throughput win).
# The exact value MUST be validated by the Phase-2 attack tooling (correlation / state-recovery),
# never assumed. 4 of 8 bytes is the conservative starting point.
OUTPUT_BYTES_PER_STEP = 4


def finalize(z: int) -> int:
    """Nonlinear ARX 'frosted-glass' output filter (the SplitMix64 / MurmurHash3 fmix64 mixer).

    Maps the 127-bit chaotic state to a well-avalanched 64-bit word with xorshift + multiply. The
    multiplications make it NONLINEAR, so the piecewise-linear PWLCM structure an attacker would use
    to invert the map is destroyed. No division, no tables => fast, Rust-friendly, constant-time.

    HONEST NOTE: this mixer is itself a bijection. The one-wayness an attacker faces comes from
    TRUNCATION (we emit only OUTPUT_BYTES_PER_STEP of the 8 bytes) + the 4-map XOR combiner — not
    from the mix alone. MEASURED in Phase 2 (attacks/differential_attack.py): no avalanche gap (every
    state bit reaches the output ~1/2), no usable single-bit differential, no published->hidden/state
    correlation, and the preimage law ~2^(w/2) holds (=> 2^32 candidates per emitted step, per map)."""
    # Fold the wide state into 64 bits FIRST so every state bit reaches the output. With the bigger
    # grid (#1) the state is up to 127 bits; a bare 64-bit mask would silently drop the top 63 bits.
    # XOR-folding the high half in keeps the whole state live. (No-op for states <= 64 bits.)
    z = (z ^ (z >> 64)) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    z ^= z >> 31
    return z


def _kdf_hash(prefix: bytes, master_key: bytes, nonce: bytes, index: int | None = None) -> bytes:
    """SHA-512 over prefix [|| index(2,BE) || '|'] || master_key || '|' || nonce.

    Returns the raw 64-byte digest. Shared across from_master(), multimap._derive_engine(),
    and ctr._block_engine() — one home, no copy-paste."""
    import hashlib

    h = hashlib.sha512(prefix)
    if index is not None:
        h.update(index.to_bytes(2, "big"))
        h.update(b"|")
    h.update(master_key)
    h.update(b"|")
    h.update(nonce)
    return h.digest()


def _derive_seed_control(h: bytes) -> tuple[int, int]:
    """From a 64-byte hash, extract (seed_key: 0..M, control_parameter: 0..HALF)."""
    seed_key = int.from_bytes(h[0:24], "big")
    control = int.from_bytes(h[24:48], "big")
    return seed_key, control


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
    # found in adversarial testing. We reject that whole neighbourhood. Defined RELATIVE to the
    # grid (HALF / 2^20) so it scales with M: the period census mirrors exactly this band.
    MIN_P = HALF >> 20

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
        # Unconditional avalanche: diffuse ANY (key, nonce) — including all-zero / tiny inputs —
        # across the full 127-bit grid. Without this, a degenerate key with nonce=0 collapses the
        # two mixes above to x = key + 1: a tiny start state that RESONATES with the map into a
        # SHORT CYCLE on the bigger grid (#1) — caught by the period-census edge probe. Two ARX
        # rounds (multiply + xorshift over M) remove that whole failure class. Deterministic, so
        # Alice and Bob still sync. (A good cipher must turn ANY key into a strong initial state.)
        x = (x * 0x9E3779B97F4A7C15) % M
        x ^= x >> 53
        x = (x * 0x2545F4914F6CDD1D + 0x9E3779B97F4A7C15) % M
        x ^= x >> 49
        x %= M
        if x == 0:
            x = DEAD_STATE_FIX
        self.x = x

        # Warm-up: discard initial outputs so the keystream doesn't expose the raw
        # key/nonce-derived state in its first bytes.
        for _ in range(16):
            self._next_state()

        # Output buffer for the multi-byte-per-step (#4) hardened output (#3). Each refill does one
        # chaotic step + one nonlinear finalize and yields OUTPUT_BYTES_PER_STEP bytes.
        self._buf = b""
        self._buf_i = 0

    @classmethod
    def from_master(cls, master_key: bytes, nonce: bytes) -> "DiscreteChaoticEngine":
        """Build an engine from arbitrary byte-string material via a hash-based KDF.

        Any master_key + nonce maps to a well-distributed seed_key and control_parameter,
        so a caller can NEVER accidentally pick a weak key — the hash output is uniform and
        the weak-parameter band is rejected in __init__ anyway. This is how the AEAD layer
        (aead.py) seeds the keystream. Deterministic => Alice and Bob still sync."""
        h = _kdf_hash(b"chaos-pwlcm-v1|seed|", master_key, nonce)
        seed_key, control = _derive_seed_control(h)
        return cls(seed_key, control, nonce=0)         # nonce already mixed into the hash

    def _next_state(self) -> None:
        """One step of the integer PWLCM — BRANCHLESS, constant-time blueprint.

        Pure integer math => bit-identical on all CPUs. This is the constant-time
        rewrite of the original 4-way `if/elif` (kept in git history): instead of
        choosing ONE of the four PWLCM segments based on the secret state (a timing
        leak — different segments could take different time), we compute ALL four
        candidate next-states every step and keep only the one whose region holds,
        via 0/1 masks. Same work regardless of the secret => no branch-timing signal.

        Output is provably identical to the original for every x in [0, M): the four
        region predicates are mutually exclusive and exhaustive over (0, M), and x==0
        / out-of-range falls through to the dead-state escape exactly as before.

        REMAINING TIMING CAVEAT (for the Rust port, not fixable in Python): the two
        divisions below are by the SECRET-derived divisors p and (HALF - p). Hardware
        integer division is data-dependent on many CPUs, so this is a second timing
        leak the branch-removal does NOT close. The Rust core must replace `// p` and
        `// (HALF - p)` with a precomputed-reciprocal multiply-shift (Barrett/Montgomery)
        computed ONCE at key setup, so the per-byte step has no secret-dependent divide.
        Both divisors are always > 0 (p in [MIN_P, HALF - MIN_P]), so every candidate is
        safe to evaluate even in the regions where it is discarded.

        WIDE-MULTIPLY NOTE (#1, the bigger grid): with M = 2^127-1 the products `M * x` are up
        to ~254 bits. Python big-ints absorb this transparently; the Rust core must do a
        128x128 -> 256-bit multiply (or fold it into the Barrett/Montgomery reduction) for each
        of the four candidates. Still constant-time — width is fixed, not secret-dependent.
        """
        x, p = self.x, self.p

        # Four PWLCM segment candidates — all evaluated every step (constant work).
        # Discarded candidates may use "wrong-region" subtractions; harmless, masked out.
        r1 = (M * x) // p                       # region (0, p)
        r2 = (M * (x - p)) // (HALF - p)        # region [p, HALF)
        r3 = (M * (M - p - x)) // (HALF - p)    # region [HALF, M - p)
        r4 = (M * (M - x)) // p                 # region [M - p, M)

        # Region masks (0 or 1). Exactly one is 1 for x in (0, M); all 0 for the dead case.
        in1 = (0 < x) & (x < p)
        in2 = (p <= x) & (x < HALF)
        in3 = (HALF <= x) & (x < (M - p))
        in4 = ((M - p) <= x) & (x < M)
        dead = not (in1 | in2 | in3 | in4)      # x == 0 (the fixed point) or out of range

        # Mask-select: sum of (candidate * its mask). Bit-identical to the if/elif chain.
        self.x = (r1 * in1) + (r2 * in2) + (r3 * in3) + (r4 * in4) + (DEAD_STATE_FIX * dead)

    def generate_byte(self) -> int:
        """Emit one hardened keystream byte. Refills from one chaotic step + the nonlinear
        finalizer (#3) when the buffer empties, taking OUTPUT_BYTES_PER_STEP bytes per step (#4).
        Replaces the old raw "(x >> 24) & 0xFF", which exposed the linear state directly."""
        if self._buf_i >= len(self._buf):
            self._next_state()
            self._buf = finalize(self.x).to_bytes(8, "big")[:OUTPUT_BYTES_PER_STEP]
            self._buf_i = 0
        b = self._buf[self._buf_i]
        self._buf_i += 1
        return b

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
