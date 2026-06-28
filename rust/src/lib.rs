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
//!  * Stage A did the per-step division `floor(M*num / den)` with a vetted big-int crate (`ruint`'s
//!    `/`). That nailed correctness and measured the speedup, but it divided by the SECRET divisor —
//!    the per-byte hot loop still had a data-dependent hardware divide (timing leak #2 OPEN).
//!  * Stage B (this file) CLOSES that leak. The per-step divide by the secret `p` / `HALF-p` is gone,
//!    replaced by a precomputed-reciprocal multiply-shift + one branchless correction. The reciprocal
//!    is computed ONCE per key at setup (where a variable-time divide is acceptable — it runs once, not
//!    per byte). The hot loop now does only multiplies, shifts, adds, and masked compares — all
//!    constant-time on fixed-width limbs. `ruint`'s big-int divide survives ONLY in `div_step_oracle`,
//!    a #[cfg(test)] reference the randomized test checks the reciprocal path against.
//!
//! THE RECIPROCAL (Barrett-style, specialized for this map):
//!   We want q = floor(M*num/d) for a fixed secret divisor d and a per-step num with num <= d+1.
//!   Precompute V = floor(M * 2^S / d) once (S = RECIP_SHIFT = 127). Then per step:
//!       q_approx = (num * V) >> S          // floor(M*num/d - delta),  0 <= delta < 1/2
//!       q        = q_approx + (rem >= d)    // exactly one correction closes the <1/2 gap
//!   where rem = M*num - q_approx*d, and M*num = (num<<127) - num because M = 2^127 - 1 (no multiply).
//!   Proof the single correction is exact: delta = num*(M*2^S mod d)/(d*2^S) < (d+1)/2^S. Every divisor
//!   here is < 2^126 (p, HALF-p both <= HALF-MIN_P), so delta < 2^126/2^127 = 1/2, hence q_approx is
//!   q-1 or q, never less and never more. The frozen KAT guarantees this stays bit-identical to Python.

use hmac::{Hmac, Mac};
use ruint::aliases::U256;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

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

/// Default independent maps per epoch — mirrors multimap.py `DEFAULT_N_MAPS` (decision #2, 4 maps).
pub const DEFAULT_N_MAPS: usize = 4;

/// Scale of the precomputed reciprocal: V = floor(M * 2^RECIP_SHIFT / d). 127 gives a truncation
/// error < 1/2 for every divisor in this map (all < 2^126), so a SINGLE branchless correction is exact.
const RECIP_SHIFT: usize = 127;

#[inline]
fn u(v: u128) -> U256 {
    U256::from_limbs([v as u64, (v >> 64) as u64, 0, 0])
}

#[inline]
fn lo128(x: U256) -> u128 {
    let l = x.as_limbs();
    (l[0] as u128) | ((l[1] as u128) << 64)
}

/// Branchless constant-time select: returns `a` if `cond == 1`, else `b`. `cond` must be 0 or 1.
/// Used to pick the per-step reciprocal by region mask without a data-dependent branch (and without
/// the two full 256-bit multiplies a mask-multiply would cost).
#[inline]
fn select(cond: u128, a: U256, b: U256) -> U256 {
    let m = (cond as u64).wrapping_neg(); // 1 -> 0xFFFF..F (all ones), 0 -> 0
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
/// Folds the 127-bit state into 64 bits so every state bit reaches the output, then ARX-mixes.
#[inline]
pub fn finalize(z: u128) -> u64 {
    let mut z = ((z ^ (z >> 64)) & (u64::MAX as u128)) as u64;
    z = (z ^ (z >> 30)).wrapping_mul(F_MUL1);
    z = (z ^ (z >> 27)).wrapping_mul(F_MUL2);
    z ^= z >> 31;
    z
}

/// Precompute the scaled reciprocal V = floor(M * 2^RECIP_SHIFT / d) for a fixed divisor d.
/// Called ONCE per divisor at key setup, so the variable-time `ruint` divide here is fine — it never
/// runs in the per-byte hot loop. V is up to ~148 bits (when d is near MIN_P), so it lives in a U256.
#[inline]
fn reciprocal(d: u128) -> U256 {
    (u(M) << RECIP_SHIFT) / u(d)
}

/// CONSTANT-TIME floor(M * num / den) via the precomputed reciprocal `recip` = reciprocal(den).
///
/// No hardware divide on the secret: q_approx = (num*recip) >> RECIP_SHIFT undershoots the true
/// quotient by at most 1 (truncation error < 1/2, proven in the module header), and one branchless
/// correction — add 1 iff the remainder M*num - q_approx*den is still >= den — makes it exact.
/// M*num is formed as (num<<127) - num because M = 2^127 - 1 (no multiply needed).
///
/// Range: num <= den+1 (the region-3 endpoint x==HALF hits den+1; all other regions give num <= den),
/// so q < M + M/MIN_P < 2^128 and fits u128. The dead case passes (num=0, den=1, recip=0) -> q=0.
#[inline]
fn div_step(num: u128, den: u128, recip: U256) -> u128 {
    let nu = u(num);
    let q_approx = (nu * recip) >> RECIP_SHIFT;
    let m_num = (nu << 127) - nu; // M * num,  M = 2^127 - 1
    let rem = m_num - q_approx * u(den); // in [0, 2*den): non-negative because q_approx <= q
    let ge = (rem >= u(den)) as u128; // 1 iff q_approx was low by one
    lo128(q_approx) + ge
}

/// Big-int reference oracle (Stage A's exact divide). TEST-ONLY: the randomized test checks the
/// constant-time `div_step` against this over millions of (num, den) pairs.
#[cfg(test)]
fn div_step_oracle(num: u128, den: u128) -> u128 {
    lo128((u(M) * u(num)) / u(den))
}

pub struct ChaosEngine {
    x: u128,
    p: u128,
    recip_p: U256,  // reciprocal(p)        — divisor for regions 1 & 4
    recip_hp: U256, // reciprocal(HALF - p) — divisor for regions 2 & 3
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

        // Precompute the two reciprocals ONCE (the only divides by the secret; not in the hot loop).
        let mut eng = ChaosEngine {
            x,
            p,
            recip_p: reciprocal(p),
            recip_hp: reciprocal(HALF - p),
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
        let sel_p = in1 | in4;
        let sel_hp = in2 | in3;
        let den = p
            .wrapping_mul(sel_p)
            .wrapping_add((HALF - p).wrapping_mul(sel_hp))
            .wrapping_add(dead); // == 1 when dead

        // Select the matching precomputed reciprocal by the same masks (recip=0 for the dead case;
        // harmless since num=0 there gives q=0). Branchless limb-select — constant-time, no big mul.
        let recip = select(sel_p, self.recip_p, select(sel_hp, self.recip_hp, U256::ZERO));

        let q = div_step(num, den, recip);
        // x = q unless dead, then the dead-state escape (q is 0 when dead)
        self.x = q.wrapping_mul(1 - dead).wrapping_add(DEAD_STATE_FIX.wrapping_mul(dead));
    }

    /// Step once and return this step's OUTPUT_BYTES_PER_STEP keystream bytes (the top bytes of the
    /// finalized state, big-endian) — the unit the multimap combiner XORs across maps. Bypasses the
    /// per-engine byte buffer, so use EITHER next_byte OR next_block on a given engine, never both.
    #[inline]
    fn next_block(&mut self) -> [u8; OUTPUT_BYTES_PER_STEP] {
        self.next_state();
        let full = finalize(self.x).to_be_bytes(); // 8 bytes, big-endian
        let mut out = [0u8; OUTPUT_BYTES_PER_STEP];
        out.copy_from_slice(&full[..OUTPUT_BYTES_PER_STEP]); // top 4 bytes, like Python
        out
    }

    #[inline]
    fn refill(&mut self) {
        let block = self.next_block();
        self.buf[..OUTPUT_BYTES_PER_STEP].copy_from_slice(&block);
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

    /// KDF constructor — mirror of engine.py `DiscreteChaoticEngine.from_master`.
    /// seed_key/control come from SHA-512 over a domain-separated message, reduced exactly as the
    /// engine reduces them, then nonce=0 (the public nonce is already folded into the hash).
    pub fn from_master(master_key: &[u8], nonce: &[u8]) -> Self {
        let h = kdf_hash(b"chaos-pwlcm-v1|seed|", None, master_key, nonce);
        let (seed, control) = derive_seed_control(&h);
        ChaosEngine::new(seed, control, 0)
    }
}

/// SHA-512 over `prefix [|| index_be(2)] || master_key || b"|" || nonce`. The `|seed|` domain
/// (from_master) passes no index; the `|multimap|` domain passes the 2-byte big-endian map index —
/// matching engine.py / multimap.py byte-for-byte.
fn kdf_hash(prefix: &[u8], index: Option<u16>, master_key: &[u8], nonce: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    if let Some(i) = index {
        hasher.update(i.to_be_bytes());
        hasher.update(b"|");
    }
    hasher.update(master_key);
    hasher.update(b"|");
    hasher.update(nonce);
    hasher.finalize().into()
}

/// Parse h[0:24] and h[24:48] as 192-bit big-endian integers and reduce them for the engine:
/// seed mod M, control mod HALF. Idempotent with ChaosEngine::new's own `% M` / `% HALF`, so the
/// 192-bit KDF output lands on exactly the same state as the Python reference.
fn derive_seed_control(h: &[u8; 64]) -> (u128, u128) {
    let seed = lo128(U256::from_be_slice(&h[0..24]) % u(M));
    let control = lo128(U256::from_be_slice(&h[24..48]) % u(HALF));
    (seed, control)
}

/// The shipped keystream: N INDEPENDENT PWLCM engines XOR-combined (mirror of multimap.py).
/// Each sub-engine gets an unrelated (seed, control) from a domain-separated, index-folded KDF.
pub struct MultiMapEngine {
    engines: Vec<ChaosEngine>,
    buf: [u8; OUTPUT_BYTES_PER_STEP], // one combined block (XOR of every map's step block)
    buf_i: usize,                     // == OUTPUT_BYTES_PER_STEP means empty
}

impl MultiMapEngine {
    pub fn new(master_key: &[u8], nonce: &[u8], n_maps: usize) -> Self {
        assert!(n_maps >= 1, "n_maps must be >= 1");
        let engines = (0..n_maps)
            .map(|i| {
                let h = kdf_hash(b"chaos-pwlcm-v1|multimap|", Some(i as u16), master_key, nonce);
                let (seed, control) = derive_seed_control(&h);
                ChaosEngine::new(seed, control, 0)
            })
            .collect();
        MultiMapEngine {
            engines,
            buf: [0u8; OUTPUT_BYTES_PER_STEP],
            buf_i: OUTPUT_BYTES_PER_STEP, // start empty -> first next_byte refills
        }
    }

    /// Step EVERY map once and XOR their per-step blocks into one combined block. The maps are fully
    /// independent, so their four dependency chains can overlap in the CPU's out-of-order window —
    /// this batched form exposes that instruction-level parallelism, where the old code interleaved
    /// the maps one byte at a time behind separate buffer-empty branches. Bit-identical: a combined
    /// byte is still the XOR over maps of each map's step bytes, exactly as before (the KAT proves it).
    #[inline]
    fn refill(&mut self) {
        let mut acc = [0u8; OUTPUT_BYTES_PER_STEP];
        for eng in self.engines.iter_mut() {
            let block = eng.next_block();
            for j in 0..OUTPUT_BYTES_PER_STEP {
                acc[j] ^= block[j];
            }
        }
        self.buf = acc;
        self.buf_i = 0;
    }

    #[inline]
    pub fn next_byte(&mut self) -> u8 {
        if self.buf_i >= OUTPUT_BYTES_PER_STEP {
            self.refill();
        }
        let b = self.buf[self.buf_i];
        self.buf_i += 1;
        b
    }

    pub fn keystream(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
    }
}

// ---- the ratchet: forward-secret, unbounded keystream (mirror of ratchet.py) ----

/// Domain-separation tag for the ratchet's key chain (must match ratchet.py `_V` byte-for-byte).
const RATCHET_V: &[u8] = b"chaos-ratchet-v1|";

type HmacSha256 = Hmac<Sha256>;

/// One-way key-derivation step: HMAC-SHA256(key, label) -> 32 bytes. Used for BOTH the chain key
/// and each epoch key, exactly like ratchet.py `_kdf`. HMAC accepts any key length, so `expect`
/// never fires.
fn hmac_sha256(key: &[u8], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

/// Concatenate byte slices into a fresh `Vec` (label building only — never the per-byte hot loop).
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

/// Auto-rekey ("A"): a one-way key chain that re-keys every `epoch_bytes` and burns the old key,
/// giving forward secrecy and an effectively unbounded stream. Drop-in for `MultiMapEngine`.
/// Bit-identical to ratchet.py — the chain, the epoch nonce (`nonce + "|ep|" + idx`), and the
/// 8-byte big-endian epoch index all mirror the Python construction.
pub struct RatchetEngine {
    nonce: Vec<u8>,
    epoch_bytes: usize,
    n_maps: usize,
    // K_{i+1}: the NEXT chain key (K_i is already burned). `Zeroizing` wipes it on drop, so the
    // final live key never lingers in freed memory.
    chain_key: Zeroizing<[u8; 32]>,
    epoch_index: u64, // the NEXT epoch to derive (current epoch is engine's)
    engine: MultiMapEngine,
    remaining: usize, // keystream bytes left before the next re-key
}

impl RatchetEngine {
    pub fn new(master_key: &[u8], nonce: &[u8], epoch_bytes: usize, n_maps: usize) -> Self {
        assert!(epoch_bytes >= 1, "epoch_bytes must be >= 1");
        // K_0 — derived from the master key, so the raw secret never seeds a map directly.
        let mut k0 = hmac_sha256(master_key, &cat(&[RATCHET_V, b"init|", nonce]));
        // Build epoch 0 inline (mirrors the `_advance()` the Python __init__ calls on entry).
        let (engine, next_chain) = Self::derive_epoch(&k0, nonce, n_maps, 0);
        k0.zeroize(); // burn K_0 — it has done its one job (deriving epoch 0 + K_1)
        RatchetEngine {
            nonce: nonce.to_vec(),
            epoch_bytes,
            n_maps,
            chain_key: Zeroizing::new(next_chain),
            epoch_index: 1,
            engine,
            remaining: epoch_bytes,
        }
    }

    /// Derive epoch `i`'s keystream engine + the next chain key from the current chain key.
    /// MK_i = HMAC(chain, V|"epoch|"|idx); K_{i+1} = HMAC(chain, V|"chain|"|idx); the epoch's engine
    /// seeds from MK_i with nonce = original_nonce|"|ep|"|idx. `idx` is the 8-byte big-endian index.
    /// MK_i is wiped here once the engine has absorbed it — the live secret is the engine state now.
    fn derive_epoch(
        chain_key: &[u8; 32],
        nonce: &[u8],
        n_maps: usize,
        epoch_index: u64,
    ) -> (MultiMapEngine, [u8; 32]) {
        let idx = epoch_index.to_be_bytes();
        let mut epoch_key = hmac_sha256(chain_key, &cat(&[RATCHET_V, b"epoch|", &idx]));
        let next_chain = hmac_sha256(chain_key, &cat(&[RATCHET_V, b"chain|", &idx]));
        let epoch_nonce = cat(&[nonce, b"|ep|", &idx]);
        let engine = MultiMapEngine::new(&epoch_key, &epoch_nonce, n_maps);
        epoch_key.zeroize(); // MK_i consumed into the engine seeds; wipe the key copy
        (engine, next_chain)
    }

    /// Step the chain into the next epoch: derive a fresh engine + chain key, then BURN K_i in place
    /// (overwrite with zeros, not just drop the reference like Python could) before storing K_{i+1}.
    fn advance(&mut self) {
        let (engine, mut next_chain) =
            Self::derive_epoch(&self.chain_key, &self.nonce, self.n_maps, self.epoch_index);
        self.engine = engine;
        self.chain_key.zeroize(); // wipe K_i in place
        self.chain_key.copy_from_slice(&next_chain); // store K_{i+1}
        next_chain.zeroize(); // drop the transient copy too
        self.epoch_index += 1;
        self.remaining = self.epoch_bytes;
    }

    #[inline]
    pub fn next_byte(&mut self) -> u8 {
        if self.remaining == 0 {
            self.advance();
        }
        self.remaining -= 1;
        self.engine.next_byte()
    }

    pub fn keystream(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
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
        // Pairings up to num == den+1 (the region-3 endpoint), so q < ~M + M/MIN_P < 2^128.
        let cases: [(u128, u128); 7] = [
            (12345, MIN_P + 12345),
            (HALF - 1, HALF),
            (MIN_P, MIN_P + 7),
            (1, HALF - MIN_P),
            (0x0123_4567_89AB_CDEF, 0x0FED_CBA9_8765_4321),
            (M / 5, M / 3),
            (MIN_P + 1, MIN_P), // num == den+1 (region-3 x==HALF case)
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

    // Deterministic xorshift128+ style PRNG so the randomized test is reproducible (no Math.random).
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
        // The Stage-B contract: the constant-time reciprocal path equals Stage-A's big-int divide
        // for EVERY (num, den) the engine can actually produce. Divisors live in [MIN_P, HALF-MIN_P]
        // (the range of both p and HALF-p); num ranges over [0, den+1] (region 3 hits den+1).
        let mut rng = Rng(0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321);
        let span = HALF - 2 * MIN_P; // width of the valid divisor band
        let divisors = if cfg!(debug_assertions) { 60 } else { 400 };
        let nums = if cfg!(debug_assertions) { 4_000 } else { 12_000 };
        for di in 0..divisors {
            // sweep the band endpoints explicitly, fill the rest at random
            let den = match di {
                0 => MIN_P,
                1 => HALF - MIN_P,
                2 => HALF / 2,
                _ => MIN_P + (rng.u128() % span),
            };
            let recip = reciprocal(den);
            // explicit edge nums first, then random ones in [0, den+1]
            for &num in &[0u128, 1, den - 1, den, den + 1] {
                assert_eq!(
                    div_step(num, den, recip),
                    div_step_oracle(num, den),
                    "edge num={num} den={den}"
                );
            }
            for _ in 0..nums {
                let num = rng.u128() % (den + 2); // [0, den+1]
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
