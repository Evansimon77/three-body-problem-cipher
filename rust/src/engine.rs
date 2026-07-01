//! Chaos PWLCM keystream core — Rust hot-loop port (Phase 4).
//!
//! This is a faithful, BIT-IDENTICAL re-implementation of the Python `DiscreteChaoticEngine`
//! (engine.py): the same integer PWLCM map on the Mersenne grid M = 2^127 - 1, the same init
//! avalanche, the same nonlinear `finalize` output mixer, the same 4-bytes-per-step buffer.
//!
//! Correctness is PROVEN, not assumed: `cargo test` checks the division invariant and the
//! finalize mixer locally, and the Python test `tests/test_rust_parity.py` checks that this
//! core reproduces every `engine_raw` vector in `kat/vectors.json` byte-for-byte.
//!
//! STAGE B (this file) CLOSES the timing leak. The per-step divide by the secret `p` / `HALF-p`
//! is gone, replaced by a precomputed-reciprocal multiply-shift + one branchless correction. The
//! reciprocal is computed ONCE per key at setup (where a variable-time divide is acceptable — it
//! runs once, not per byte). The hot loop now does only multiplies, shifts, adds, and masked
//! compares — all constant-time on fixed-width limbs.

use ruint::aliases::U256;

// ---- grid constants (mirror engine.py exactly) ----
pub(crate) const M: u128 = (1u128 << 127) - 1; // Mersenne prime M127
pub(crate) const HALF: u128 = M / 2; // 2^126 - 1
pub(crate) const MIN_P: u128 = HALF >> 20;
pub(crate) const DEAD_STATE_FIX: u128 = 0x5555_5555_5555_5555_5555_5555_5555_5555; // < M, so % M is itself

const K_GOLDEN: u128 = 0x9E37_79B9_7F4A_7C15;
const K_MIX: u128 = 0x2545_F491_4F6C_DD1D;
const F_MUL1: u64 = 0xBF58_476D_1CE4_E5B9;
const F_MUL2: u64 = 0x94D0_49BB_1331_11EB;

pub(crate) const OUTPUT_BYTES_PER_STEP: usize = 4;

/// Scale of the precomputed reciprocal: V = floor(M * 2^RECIP_SHIFT / d). 127 gives a truncation
/// error < 1/2 for every divisor in this map (all < 2^126), so a SINGLE branchless correction is exact.
const RECIP_SHIFT: usize = 127;

#[inline]
pub(crate) fn u(v: u128) -> U256 {
    U256::from_limbs([v as u64, (v >> 64) as u64, 0, 0])
}

#[inline]
pub(crate) fn lo128(x: U256) -> u128 {
    let l = x.as_limbs();
    (l[0] as u128) | ((l[1] as u128) << 64)
}

/// Branchless constant-time select: returns `a` if `cond == 1`, else `b`. `cond` must be 0 or 1.
#[inline]
fn select(cond: u128, a: U256, b: U256) -> U256 {
    let m = (cond as u64).wrapping_neg();
    let (la, lb) = (a.as_limbs(), b.as_limbs());
    U256::from_limbs([
        (la[0] & m) | (lb[0] & !m),
        (la[1] & m) | (lb[1] & !m),
        (la[2] & m) | (lb[2] & !m),
        (la[3] & m) | (lb[3] & !m),
    ])
}

/// (a * b) mod M, for a, b < 2^127. Used only at key setup (the init avalanche), not per byte.
#[inline]
fn mulmod_m(a: u128, b: u128) -> u128 {
    lo128((u(a) * u(b)) % u(M))
}

/// The nonlinear "frosted-glass" output mixer (SplitMix64 / fmix64), identical to engine._finalize.
#[inline]
pub(crate) fn finalize(z: u128) -> u64 {
    let mut z = ((z ^ (z >> 64)) & (u64::MAX as u128)) as u64;
    z = (z ^ (z >> 30)).wrapping_mul(F_MUL1);
    z = (z ^ (z >> 27)).wrapping_mul(F_MUL2);
    z ^= z >> 31;
    z
}

/// Precompute the scaled reciprocal V = floor(M * 2^RECIP_SHIFT / d) for a fixed divisor d.
#[inline]
fn reciprocal(d: u128) -> U256 {
    (u(M) << RECIP_SHIFT) / u(d)
}

/// CONSTANT-TIME floor(M * num / den) via the precomputed reciprocal.
///
/// No hardware divide on the secret: q_approx = (num*recip) >> RECIP_SHIFT undershoots the true
/// quotient by at most 1, and one branchless correction makes it exact.
#[inline]
fn div_step(num: u128, den: u128, recip: U256) -> u128 {
    let nu = u(num);
    let q_approx = (nu * recip) >> RECIP_SHIFT;
    let m_num = (nu << 127) - nu;
    let rem = m_num - q_approx * u(den);
    let ge = (rem >= u(den)) as u128;
    lo128(q_approx) + ge
}

/// Big-int reference oracle (Stage A's exact divide). TEST-ONLY.
#[cfg(test)]
fn div_step_oracle(num: u128, den: u128) -> u128 {
    lo128((u(M) * u(num)) / u(den))
}

pub struct ChaosEngine {
    x: u128,
    p: u128,
    recip_p: U256,
    recip_hp: U256,
    buf: [u8; 8],
    buf_len: usize,
    buf_i: usize,
}

impl ChaosEngine {
    /// Mirror of DiscreteChaoticEngine.__init__(seed_key, control_parameter, nonce).
    pub fn new(seed_key: u128, control_parameter: u128, nonce: u128) -> Self {
        let mut p = control_parameter % HALF;
        if !(MIN_P <= p && p <= HALF - MIN_P) {
            p = MIN_P + (p % (HALF - 2 * MIN_P));
        }

        let m256 = u(M);
        let mut x = u(seed_key % M);
        let nn = nonce % M;
        x = (x ^ u(mulmod_m(nn, K_GOLDEN))) % m256;
        x = (x + ((u(nn) << 17) % m256) + U256::from(1u8)) % m256;
        x = (x * u(K_GOLDEN)) % m256;
        x ^= x >> 53;
        x = (x * u(K_MIX) + u(K_GOLDEN)) % m256;
        x ^= x >> 49;
        x %= m256;
        let mut x = lo128(x);
        if x == 0 {
            x = DEAD_STATE_FIX;
        }

        let mut eng = ChaosEngine {
            x,
            p,
            recip_p: reciprocal(p),
            recip_hp: reciprocal(HALF - p),
            buf: [0u8; 8],
            buf_len: 0,
            buf_i: 0,
        };
        for _ in 0..16 {
            eng.next_state();
        }
        eng
    }

    /// One PWLCM step — constant-time, branchless.
    #[inline]
    fn next_state(&mut self) {
        let x = self.x;
        let p = self.p;

        let in1 = ((x > 0) & (x < p)) as u128;
        let in2 = ((x >= p) & (x < HALF)) as u128;
        let in3 = ((x >= HALF) & (x < (M - p))) as u128;
        let in4 = ((x >= (M - p)) & (x < M)) as u128;
        let dead = 1u128 - (in1 | in2 | in3 | in4);

        let n1 = x;
        let n2 = x.wrapping_sub(p);
        let n3 = M.wrapping_sub(p).wrapping_sub(x);
        let n4 = M.wrapping_sub(x);
        let num = n1
            .wrapping_mul(in1)
            .wrapping_add(n2.wrapping_mul(in2))
            .wrapping_add(n3.wrapping_mul(in3))
            .wrapping_add(n4.wrapping_mul(in4));

        let sel_p = in1 | in4;
        let sel_hp = in2 | in3;
        let den = p
            .wrapping_mul(sel_p)
            .wrapping_add((HALF - p).wrapping_mul(sel_hp))
            .wrapping_add(dead);

        let recip = select(sel_p, self.recip_p, select(sel_hp, self.recip_hp, U256::ZERO));
        let q = div_step(num, den, recip);
        self.x = q.wrapping_mul(1 - dead).wrapping_add(DEAD_STATE_FIX.wrapping_mul(dead));
    }

    /// Step once and return this step's OUTPUT_BYTES_PER_STEP keystream bytes.
    #[inline]
    pub fn next_block(&mut self) -> [u8; OUTPUT_BYTES_PER_STEP] {
        self.next_state();
        let full = finalize(self.x).to_be_bytes();
        let mut out = [0u8; OUTPUT_BYTES_PER_STEP];
        out.copy_from_slice(&full[..OUTPUT_BYTES_PER_STEP]);
        out
    }

    #[inline]
    fn refill(&mut self) {
        let block = self.next_block();
        self.buf[..OUTPUT_BYTES_PER_STEP].copy_from_slice(&block);
        self.buf_len = OUTPUT_BYTES_PER_STEP;
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

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let ks = self.keystream(data.len());
        data.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect()
    }

    /// KDF constructor — mirror of engine.py `DiscreteChaoticEngine.from_master`.
    pub fn from_master(master_key: &[u8], nonce: &[u8]) -> Self {
        let h = crate::utils::kdf_hash(b"chaos-pwlcm-v1|seed|", None, master_key, nonce);
        let (seed, control) = crate::utils::derive_seed_control(&h);
        ChaosEngine::new(seed, control, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_matches_known_answer() {
        assert_eq!(finalize(1), 0x5692_161d_100b_05e5);
        assert_eq!(finalize(0), 0);
    }

    #[test]
    fn div_step_invariant_holds() {
        let cases: [(u128, u128); 7] = [
            (12345, MIN_P + 12345),
            (HALF - 1, HALF),
            (MIN_P, MIN_P + 7),
            (1, HALF - MIN_P),
            (0x0123_4567_89AB_CDEF, 0x0FED_CBA9_8765_4321),
            (M / 5, M / 3),
            (MIN_P + 1, MIN_P),
        ];
        for (num, den) in cases {
            let q = div_step(num, den, reciprocal(den));
            let n = u(M) * u(num);
            let lhs = u(q) * u(den);
            let rhs = u(q.wrapping_add(1)) * u(den);
            assert!(lhs <= n, "q*den <= M*num failed for ({num},{den})");
            assert!(n < rhs, "M*num < (q+1)*den failed for ({num},{den})");
        }
    }

    struct Rng(u64, u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut s1 = self.0;
            let s0 = self.1;
            self.0 = s0;
            s1 ^= s1 << 23;
            self.1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
            self.1.wrapping_add(s0)
        }
        fn u128(&mut self) -> u128 {
            ((self.next() as u128) << 64) | (self.next() as u128)
        }
    }

    #[test]
    fn recip_div_matches_bigint_oracle() {
        let mut rng = Rng(0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321);
        let span = HALF - 2 * MIN_P;
        let divisors = if cfg!(debug_assertions) { 60 } else { 400 };
        let nums = if cfg!(debug_assertions) { 4_000 } else { 12_000 };
        for di in 0..divisors {
            let den = match di {
                0 => MIN_P,
                1 => HALF - MIN_P,
                2 => HALF / 2,
                _ => MIN_P + (rng.u128() % span),
            };
            let recip = reciprocal(den);
            for &num in &[0u128, 1, den - 1, den, den + 1] {
                assert_eq!(
                    div_step(num, den, recip),
                    div_step_oracle(num, den),
                    "edge num={num} den={den}"
                );
            }
            for _ in 0..nums {
                let num = rng.u128() % (den + 2);
                assert_eq!(
                    div_step(num, den, recip),
                    div_step_oracle(num, den),
                    "num={num} den={den}"
                );
            }
        }
    }

    #[test]
    fn keystream_is_deterministic() {
        let a = ChaosEngine::new(11, 22, 33).keystream(64);
        let b = ChaosEngine::new(11, 22, 33).keystream(64);
        assert_eq!(a, b);
    }
}
