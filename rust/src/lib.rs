//! Chaos PWLCM keystream core — Rust hot-loop port (Phase 4, Stage A).
//!
//! This is a faithful, BIT-IDENTICAL re-implementation of the Python `DiscreteChaoticEngine`
//! (engine.py): the same integer PWLCM map on the Mersenne grid M = 2^127 - 1, the same init
//! avalanche, the same nonlinear `finalize` output mixer, the same 4-bytes-per-step buffer.
//!
//! Correctness is PROVEN, not assumed: `cargo test` checks the division invariant and the
//! finalize mixer locally, and the Python test `tests/test_rust_parity.py` checks that this
//! core reproduces every `engine_raw` vector in `kat/vectors.json` byte-for-byte.
//!
//! STAGE A vs STAGE B:
//!  * Stage A (this file) does the per-step division `floor(M*num / den)` with a vetted big-int
//!    crate. This nails correctness and lets us measure the speedup. It still divides by the
//!    secret divisor, so the timing leak #2 is NOT yet closed here — same open status as Python.
//!  * Stage B will replace `div_step` with a hand-rolled constant-time precomputed reciprocal
//!    (Barrett/Montgomery) computed once at key setup, closing the divide timing leak. The KAT
//!    guarantees that swap stays bit-identical.

use ruint::aliases::U256;

// ---- grid constants (mirror engine.py exactly) ----
pub const M: u128 = (1u128 << 127) - 1; // Mersenne prime M127
pub const HALF: u128 = M / 2; // 2^126 - 1
pub const MIN_P: u128 = HALF >> 20;
pub const DEAD_STATE_FIX: u128 = 0x5555_5555_5555_5555_5555_5555_5555_5555; // < M, so % M is itself

const K_GOLDEN: u128 = 0x9E37_79B9_7F4A_7C15;
const K_MIX: u128 = 0x2545_F491_4F6C_DD1D;
const F_MUL1: u64 = 0xBF58_476D_1CE4_E5B9;
const F_MUL2: u64 = 0x94D0_49BB_1331_11EB;

pub const OUTPUT_BYTES_PER_STEP: usize = 4;

#[inline]
fn u(v: u128) -> U256 {
    U256::from_limbs([v as u64, (v >> 64) as u64, 0, 0])
}

#[inline]
fn lo128(x: U256) -> u128 {
    let l = x.as_limbs();
    (l[0] as u128) | ((l[1] as u128) << 64)
}

/// (a * b) mod M, for a, b < 2^127. Used only at key setup (the init avalanche), not per byte.
#[inline]
fn mulmod_m(a: u128, b: u128) -> u128 {
    lo128((u(a) * u(b)) % u(M))
}

/// The nonlinear "frosted-glass" output mixer (SplitMix64 / fmix64), identical to engine._finalize.
/// Folds the 127-bit state into 64 bits so every state bit reaches the output, then ARX-mixes.
#[inline]
pub fn finalize(z: u128) -> u64 {
    let mut z = ((z ^ (z >> 64)) & (u64::MAX as u128)) as u64;
    z = (z ^ (z >> 30)).wrapping_mul(F_MUL1);
    z = (z ^ (z >> 27)).wrapping_mul(F_MUL2);
    z ^= z >> 31;
    z
}

/// floor(M * num / den) as u128.
///
/// PRECONDITION: num <= den (which always holds for the SELECTED PWLCM candidate in every region),
/// so the quotient is < ~2M < 2^128 and fits in u128. Off-region candidates are masked out before
/// they reach here, so this is never called with the num > den pairings that would overflow.
/// STAGE A: big-int division (not yet constant-time). STAGE B will swap this for a reciprocal.
#[inline]
fn div_step(num: u128, den: u128) -> u128 {
    lo128((u(M) * u(num)) / u(den))
}

pub struct ChaosEngine {
    x: u128,
    p: u128,
    buf: [u8; 8],
    buf_len: usize, // valid bytes in buf (= OUTPUT_BYTES_PER_STEP after a refill)
    buf_i: usize,
}

impl ChaosEngine {
    /// Mirror of DiscreteChaoticEngine.__init__(seed_key, control_parameter, nonce).
    pub fn new(seed_key: u128, control_parameter: u128, nonce: u128) -> Self {
        // --- break-point p with weak-parameter rejection ---
        let mut p = control_parameter % HALF;
        if !(MIN_P <= p && p <= HALF - MIN_P) {
            p = MIN_P + (p % (HALF - 2 * MIN_P));
        }

        // --- init avalanche (all mod M); follows engine.py line-for-line ---
        let m256 = u(M);
        let mut x = u(seed_key % M);
        let nn = nonce % M;
        // x = (x ^ (n*K_GOLDEN % M)) % M
        x = (x ^ u(mulmod_m(nn, K_GOLDEN))) % m256;
        // x = (x + (n<<17 % M) + 1) % M
        x = (x + ((u(nn) << 17) % m256) + U256::from(1u8)) % m256;
        // x = (x * K_GOLDEN) % M
        x = (x * u(K_GOLDEN)) % m256;
        // x ^= x >> 53   (no mod)
        x ^= x >> 53;
        // x = (x * K_MIX + K_GOLDEN) % M
        x = (x * u(K_MIX) + u(K_GOLDEN)) % m256;
        // x ^= x >> 49   (no mod)
        x ^= x >> 49;
        x %= m256;
        let mut x = lo128(x);
        if x == 0 {
            x = DEAD_STATE_FIX;
        }

        let mut eng = ChaosEngine {
            x,
            p,
            buf: [0u8; 8],
            buf_len: 0,
            buf_i: 0,
        };
        // warm-up: discard 16 states
        for _ in 0..16 {
            eng.next_state();
        }
        eng
    }

    /// One PWLCM step — single masked numerator/divisor select + one division.
    /// Branchless in shape (the structure Stage B needs); only one candidate contributes.
    #[inline]
    fn next_state(&mut self) {
        let x = self.x;
        let p = self.p;

        // region masks (exactly one is 1 for x in (0, M); all 0 only for x == 0 / out of range)
        let in1 = ((x > 0) & (x < p)) as u128;
        let in2 = ((x >= p) & (x < HALF)) as u128;
        let in3 = ((x >= HALF) & (x < (M - p))) as u128;
        let in4 = ((x >= (M - p)) & (x < M)) as u128;
        let dead = 1u128 - (in1 | in2 | in3 | in4);

        // candidate numerators (wrapping; masked-out ones contribute 0 to the sum)
        let n1 = x;
        let n2 = x.wrapping_sub(p);
        let n3 = M.wrapping_sub(p).wrapping_sub(x);
        let n4 = M.wrapping_sub(x);
        let num = n1
            .wrapping_mul(in1)
            .wrapping_add(n2.wrapping_mul(in2))
            .wrapping_add(n3.wrapping_mul(in3))
            .wrapping_add(n4.wrapping_mul(in4));

        // divisor: p for regions 1&4, (HALF-p) for regions 2&3, 1 for the dead case (num=0 there)
        let den = p
            .wrapping_mul(in1 | in4)
            .wrapping_add((HALF - p).wrapping_mul(in2 | in3))
            .wrapping_add(dead); // == 1 when dead

        let q = div_step(num, den);
        // x = q unless dead, then the dead-state escape (q is 0 when dead)
        self.x = q.wrapping_mul(1 - dead).wrapping_add(DEAD_STATE_FIX.wrapping_mul(dead));
    }

    #[inline]
    fn refill(&mut self) {
        self.next_state();
        self.buf = finalize(self.x).to_be_bytes();
        self.buf_len = OUTPUT_BYTES_PER_STEP; // emit the top 4 bytes (big-endian), like Python
        self.buf_i = 0;
    }

    #[inline]
    pub fn next_byte(&mut self) -> u8 {
        if self.buf_i >= self.buf_len {
            self.refill();
        }
        let b = self.buf[self.buf_i];
        self.buf_i += 1;
        b
    }

    pub fn keystream(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.next_byte());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_matches_known_answer() {
        // From kat/vectors.json: finalize(1) = 0x5692161d100b05e5
        assert_eq!(finalize(1), 0x5692_161d_100b_05e5);
        assert_eq!(finalize(0), 0); // fmix64(0) == 0
    }

    #[test]
    fn div_step_invariant_holds() {
        // q = floor(M*num/den) must satisfy q*den <= M*num < (q+1)*den.
        // Realistic pairings only: num <= den (the engine's region invariant), so q < ~2M < 2^128.
        let cases: [(u128, u128); 6] = [
            (12345, MIN_P + 12345),
            (HALF - 1, HALF),
            (MIN_P, MIN_P + 7),
            (1, HALF - MIN_P),
            (0x0123_4567_89AB_CDEF, 0x0FED_CBA9_8765_4321),
            (M / 5, M / 3),
        ];
        for (num, den) in cases {
            let q = div_step(num, den);
            let n = u(M) * u(num);
            let lhs = u(q) * u(den);
            let rhs = u(q.wrapping_add(1)) * u(den);
            assert!(lhs <= n, "q*den <= M*num failed for ({num},{den})");
            assert!(n < rhs, "M*num < (q+1)*den failed for ({num},{den})");
        }
    }

    #[test]
    fn keystream_is_deterministic() {
        let a = ChaosEngine::new(11, 22, 33).keystream(64);
        let b = ChaosEngine::new(11, 22, 33).keystream(64);
        assert_eq!(a, b);
    }
}
