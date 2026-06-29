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
    // `as Mac` disambiguates: the two-locks section (Phase 8.4) brings `aead::KeyInit` into crate
    // scope, and HmacSha256 implements both KeyInit and Mac — name the trait we want explicitly.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
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

// ---- the committing AEAD shell (Phase 8.1): a full seal/open over the multimap keystream ----
//
// Bit-identical port of aead.py + commit.py. The chaos keystream is the (UNVETTED) bulk cipher; the
// integrity and key-commitment ride vetted HMAC-SHA256 (the `hmac`/`sha2` crates — NOT hand-rolled).
//
//   wire format:  nonce(16) || commit(32) || ciphertext(N) || tag(32)
//   commit  = HMAC( HMAC(key, "commit-key-info"), nonce || len(aad) || aad )   (CMT-4 key-commitment)
//   tag     = HMAC( HMAC(key, "mac-key-info"),    nonce || commit || len(aad) || aad || ciphertext )
//
// `seal` takes an explicit nonce (the Python shell draws a fresh random one per call; the determinism
// lives here so the frozen KAT can pin a full encrypt/decrypt). `open` returns None on any failure —
// wrong key, tamper, or a failed commitment — and NEVER returns plaintext in that case.

pub const NONCE_LEN: usize = 16;
pub const COMMIT_LEN: usize = 32;
pub const TAG_LEN: usize = 32;

const COMMIT_KEY_INFO: &[u8] = b"chaos-pwlcm-v1|commit-key|v1"; // commit.py _COMMIT_KEY_INFO
const MAC_INFO: &[u8] = b"chaos-pwlcm-v1|mac-key"; // aead.py _MAC_INFO

/// HMAC-SHA256 over several parts in order (incremental, no intermediate concat). Mirrors Python's
/// `hmac.new(key).update(p) ...` so the byte stream fed to the MAC is identical.
fn hmac_sha256_multi(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // `as Mac` disambiguates: the two-locks section (Phase 8.4) brings `aead::KeyInit` into crate
    // scope, and HmacSha256 implements both KeyInit and Mac — name the trait we want explicitly.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Constant-time byte equality (mirror of `hmac.compare_digest`): no early-out on the first mismatch,
/// so a wrong tag/commitment leaks no timing about where it diverged.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// CMT-4 key-commitment binding the master key to (salt, aad). Mirror of commit.py.
pub fn key_commitment(master_key: &[u8], salt: &[u8], aad: &[u8]) -> [u8; 32] {
    let k_c = hmac_sha256(master_key, COMMIT_KEY_INFO);
    let alen = (aad.len() as u64).to_be_bytes();
    hmac_sha256_multi(&k_c, &[salt, &alen, aad])
}

/// Encrypt-then-MAC tag over nonce + commitment + length-prefixed aad + ciphertext. Mirror of aead._tag.
fn aead_tag(master_key: &[u8], nonce: &[u8], commit: &[u8], aad: &[u8], ct: &[u8]) -> [u8; 32] {
    let mac_key = hmac_sha256(master_key, MAC_INFO);
    let alen = (aad.len() as u64).to_be_bytes();
    hmac_sha256_multi(&mac_key, &[nonce, commit, &alen, aad, ct])
}

/// Seal: nonce || commit || (plaintext XOR keystream) || tag. Deterministic in the given nonce.
pub fn aead_seal(master_key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8], n_maps: usize) -> Vec<u8> {
    let ks = MultiMapEngine::new(master_key, nonce, n_maps).keystream(plaintext.len());
    let ct: Vec<u8> = plaintext.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect();
    let commit = key_commitment(master_key, nonce, aad);
    let tag = aead_tag(master_key, nonce, &commit, aad, &ct);
    let mut blob = Vec::with_capacity(NONCE_LEN + COMMIT_LEN + ct.len() + TAG_LEN);
    blob.extend_from_slice(&nonce[..NONCE_LEN]);
    blob.extend_from_slice(&commit);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    blob
}

/// Open: verify tag (constant-time) THEN the key-commitment, then decrypt. None on any failure.
pub fn aead_open(master_key: &[u8], blob: &[u8], aad: &[u8], n_maps: usize) -> Option<Vec<u8>> {
    if blob.len() < NONCE_LEN + COMMIT_LEN + TAG_LEN {
        return None;
    }
    let nonce = &blob[..NONCE_LEN];
    let commit = &blob[NONCE_LEN..NONCE_LEN + COMMIT_LEN];
    let tag = &blob[blob.len() - TAG_LEN..];
    let ct = &blob[NONCE_LEN + COMMIT_LEN..blob.len() - TAG_LEN];

    let expected_tag = aead_tag(master_key, nonce, commit, aad, ct);
    if !ct_eq(&expected_tag, tag) {
        return None;
    }
    let expected_commit = key_commitment(master_key, nonce, aad);
    if !ct_eq(&expected_commit, commit) {
        return None;
    }
    let ks = MultiMapEngine::new(master_key, nonce, n_maps).keystream(ct.len());
    Some(ct.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect())
}

// ---- streaming AEAD (Phase 8.2): the STREAM construction (bit-identical port of streaming.py) ----
//
// Encrypt a big payload chunk-by-chunk. Each chunk's HMAC binds its index + a `final` flag, so
// reorder / drop / duplicate / truncate are all caught on top of tamper; the header carries a
// key-commitment. Wire format (self-delimiting one-shot form, mirror of seal_stream/open_stream):
//   header : salt(16) || commit(32)
//   frame  : framelen(4, big-endian) || flags(1) || ciphertext(N) || tag(32)   [framelen = 1+N+32]
//   per chunk i:  nonce_i = salt || i(8,BE) || flags ; tag_i = HMAC(stream_mac_key,
//                 salt || i(8,BE) || flags || len(aad)(8,BE) || aad || ct_i)

pub const SALT_LEN: usize = 16;
pub const HEADER_LEN: usize = SALT_LEN + COMMIT_LEN;
const STREAM_MAC_INFO: &[u8] = b"chaos-pwlcm-v1|stream-mac-key";
const FINAL_FLAG: u8 = 0x01;
const FRAME_LEN_BYTES: usize = 4;

fn stream_mac_key(master_key: &[u8]) -> [u8; 32] {
    hmac_sha256(master_key, STREAM_MAC_INFO)
}

fn chunk_tag(mac_key: &[u8], salt: &[u8], index: u64, flags: u8, aad: &[u8], ct: &[u8]) -> [u8; 32] {
    let idx = index.to_be_bytes();
    let alen = (aad.len() as u64).to_be_bytes();
    hmac_sha256_multi(mac_key, &[salt, &idx, &[flags], &alen, aad, ct])
}

fn chunk_nonce(salt: &[u8], index: u64, flags: u8) -> Vec<u8> {
    let mut n = Vec::with_capacity(SALT_LEN + 8 + 1);
    n.extend_from_slice(salt);
    n.extend_from_slice(&index.to_be_bytes());
    n.push(flags);
    n
}

/// Seal a list of chunks into one self-delimiting blob. Deterministic in the given salt (the only
/// nondeterminism in the Python shell). An empty list emits a single empty final chunk.
pub fn stream_seal(master_key: &[u8], salt: &[u8], chunks: &[&[u8]], aad: &[u8], n_maps: usize) -> Vec<u8> {
    let mac_key = stream_mac_key(master_key);
    let mut out = Vec::new();
    out.extend_from_slice(&salt[..SALT_LEN]);
    out.extend_from_slice(&key_commitment(master_key, salt, aad));

    let single_empty: [&[u8]; 1] = [b""];
    let chunks: &[&[u8]] = if chunks.is_empty() { &single_empty } else { chunks };
    let last = chunks.len() - 1;
    for (i, c) in chunks.iter().enumerate() {
        let flags = if i == last { FINAL_FLAG } else { 0 };
        let nonce = chunk_nonce(salt, i as u64, flags);
        let ks = MultiMapEngine::new(master_key, &nonce, n_maps).keystream(c.len());
        let ct: Vec<u8> = c.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect();
        let tag = chunk_tag(&mac_key, salt, i as u64, flags, aad, &ct);
        let frame_len = (1 + ct.len() + TAG_LEN) as u32;
        out.extend_from_slice(&frame_len.to_be_bytes());
        out.push(flags);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
    }
    out
}

/// Verify + decrypt a blob made by `stream_seal`. None on any manipulation (tamper / reorder / drop /
/// duplicate / truncate / trailing data / wrong key). Returns the concatenated plaintext otherwise.
pub fn stream_open(master_key: &[u8], blob: &[u8], aad: &[u8], n_maps: usize) -> Option<Vec<u8>> {
    if blob.len() < HEADER_LEN {
        return None;
    }
    let salt = &blob[..SALT_LEN];
    let commit = &blob[SALT_LEN..HEADER_LEN];
    if !ct_eq(&key_commitment(master_key, salt, aad), commit) {
        return None;
    }
    let mac_key = stream_mac_key(master_key);
    let mut pos = HEADER_LEN;
    let mut out = Vec::new();
    let mut index: u64 = 0;
    let mut saw_final = false;
    while pos < blob.len() {
        if pos + FRAME_LEN_BYTES > blob.len() {
            return None;
        }
        let flen = u32::from_be_bytes(blob[pos..pos + FRAME_LEN_BYTES].try_into().ok()?) as usize;
        pos += FRAME_LEN_BYTES;
        if pos + flen > blob.len() || flen < 1 + TAG_LEN {
            return None;
        }
        let frame = &blob[pos..pos + flen];
        pos += flen;
        let flags = frame[0];
        let ct = &frame[1..frame.len() - TAG_LEN];
        let tag = &frame[frame.len() - TAG_LEN..];
        let expected = chunk_tag(&mac_key, salt, index, flags, aad, ct);
        if !ct_eq(&expected, tag) {
            return None;
        }
        let nonce = chunk_nonce(salt, index, flags);
        let ks = MultiMapEngine::new(master_key, &nonce, n_maps).keystream(ct.len());
        out.extend(ct.iter().zip(ks.iter()).map(|(c, k)| c ^ k));
        index += 1;
        if flags & FINAL_FLAG != 0 {
            saw_final = true;
            break;
        }
    }
    if pos != blob.len() || !saw_final {
        return None; // trailing data after final, or truncated (never saw final)
    }
    Some(out)
}

// ---- ratchet session AEAD (Phase 8.3): forward-secret SESSION over the committing AEAD ----
//
// Bit-identical port of ratchet_aead.py. A session of messages where each message gets its OWN key
// from a one-way HMAC-SHA256 chain (advanced once per message); the link that made a key is burned
// after use. Capture the live session state after message N and you can read N onward (the live
// state) but NOT 0..N-1 — their keys are gone and the chain is one-way. Each message is sealed with
// the ordinary committing AEAD (`aead_seal`, Phase 8.1), so it inherits confidentiality + integrity
// + key-commitment for free; this layer only adds the forward-secret keying.
//
//   chain_0     = HMAC(master_key, V|"init|"|nonce)
//   msg_key_i   = HMAC(chain_i,    V|"msg|" |i)        // this message's AEAD key
//   chain_{i+1} = HMAC(chain_i,    V|"chain|"|i)       // next link; then BURN chain_i
//   wire_i      = i(8,BE) || aead_seal(msg_key_i, inner_nonce_i, plaintext, bind_aad(aad, i))
//
// The index i is sealed INTO the inner AEAD's aad, so a tampered wire index fails to open. Like the
// Python `aead.seal`, the inner nonce is the only source of nondeterminism; the Python shell draws it
// at random, the Rust core takes it explicitly (same as `aead_seal`) so the caller owns randomness
// and the KAT can pin it. zeroize CLOSES the burn in memory (Python's `del` is best-effort): each
// retired chain link is wiped in place, and the live link wiped on drop.

/// Domain-separation tag for the session-AEAD chain (must match ratchet_aead.py `_V` byte-for-byte).
const RATCHET_AEAD_V: &[u8] = b"chaos-ratchet-aead-v1|";

/// chain_0, derived from the master key so the raw secret never keys a message directly.
fn ra_init_chain(master_key: &[u8], nonce: &[u8]) -> [u8; 32] {
    hmac_sha256(master_key, &cat(&[RATCHET_AEAD_V, b"init|", nonce]))
}

/// From chain_i return (msg_key_i, chain_{i+1}). The caller burns chain_i afterwards.
fn ra_derive(chain: &[u8; 32], index: u64) -> ([u8; 32], [u8; 32]) {
    let idx = index.to_be_bytes();
    let msg_key = hmac_sha256(chain, &cat(&[RATCHET_AEAD_V, b"msg|", &idx]));
    let next_chain = hmac_sha256(chain, &cat(&[RATCHET_AEAD_V, b"chain|", &idx]));
    (msg_key, next_chain)
}

/// Authenticate the message index inside the inner AEAD: length-prefix the caller's aad, then append
/// the index (mirror of ratchet_aead._bind_aad). A tampered wire index won't match here -> open fails.
fn ra_bind_aad(aad: &[u8], index: u64) -> Vec<u8> {
    let alen = (aad.len() as u64).to_be_bytes();
    cat(&[&alen, aad, &index.to_be_bytes()])
}

/// Shared chain state for a forward-secret session. Sender and receiver each hold one and advance it
/// in lockstep. `chain` is the CURRENT link chain_i (wiped in place when stepped past); `index` is the
/// next message index to produce / expect.
struct RatchetAeadSession {
    aad: Vec<u8>,
    chain: Zeroizing<[u8; 32]>,
    index: u64,
    n_maps: usize,
}

impl RatchetAeadSession {
    fn new(master_key: &[u8], nonce: &[u8], aad: &[u8], n_maps: usize) -> Self {
        RatchetAeadSession {
            aad: aad.to_vec(),
            chain: Zeroizing::new(ra_init_chain(master_key, nonce)),
            index: 0,
            n_maps,
        }
    }

    /// Advance one link: return (this index, its message key) and BURN the consumed chain link in
    /// place. The returned key is `Zeroizing`, so the caller's copy is wiped when it drops too.
    fn step(&mut self) -> (u64, Zeroizing<[u8; 32]>) {
        let i = self.index;
        let (msg_key, mut next_chain) = ra_derive(&self.chain, i);
        self.chain.zeroize(); // burn chain_i in place (Python could only drop the reference)
        self.chain.copy_from_slice(&next_chain);
        next_chain.zeroize(); // drop the transient copy too
        self.index += 1;
        (i, Zeroizing::new(msg_key))
    }
}

/// Seal a sequence of messages with per-message forward secrecy (mirror of SenderSession).
pub struct RatchetAeadSender(RatchetAeadSession);

impl RatchetAeadSender {
    pub fn new(master_key: &[u8], nonce: &[u8], aad: &[u8], n_maps: usize) -> Self {
        RatchetAeadSender(RatchetAeadSession::new(master_key, nonce, aad, n_maps))
    }

    /// Seal the next message. Returns index(8,BE) || committing-AEAD blob. After this returns the key
    /// for THIS message is gone from the session. `inner_nonce` is the inner AEAD nonce (16 bytes) —
    /// the caller supplies it (the Python shell randomizes it; here the caller owns randomness).
    pub fn seal(&mut self, inner_nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let (i, msg_key) = self.0.step();
        let aad = ra_bind_aad(&self.0.aad, i);
        let blob = aead_seal(&msg_key[..], inner_nonce, plaintext, &aad, self.0.n_maps);
        let mut wire = Vec::with_capacity(8 + blob.len());
        wire.extend_from_slice(&i.to_be_bytes());
        wire.extend_from_slice(&blob);
        wire
    }
}

/// Open a sequence of messages sealed by a `RatchetAeadSender`, advancing the chain in lockstep
/// (mirror of ReceiverSession). Forward secrecy: a message whose index is in the PAST (its key was
/// already burned) returns None — that is the guarantee working, not a failure to decrypt.
pub struct RatchetAeadReceiver(RatchetAeadSession);

impl RatchetAeadReceiver {
    pub fn new(master_key: &[u8], nonce: &[u8], aad: &[u8], n_maps: usize) -> Self {
        RatchetAeadReceiver(RatchetAeadSession::new(master_key, nonce, aad, n_maps))
    }

    /// Open the next message. None on tamper / wrong key, or if the index is in the past (key burned).
    /// Gaps are tolerated by fast-forwarding (and burning) the skipped links, exactly like Python.
    pub fn open(&mut self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() < 8 {
            return None;
        }
        let i = u64::from_be_bytes(wire[..8].try_into().ok()?);
        if i < self.0.index {
            return None; // in the past — its key was burned (forward secrecy)
        }
        while self.0.index < i {
            let _ = self.0.step(); // fast-forward + burn skipped links (Zeroizing wipes each key)
        }
        let (j, msg_key) = self.0.step();
        debug_assert_eq!(j, i);
        let aad = ra_bind_aad(&self.0.aad, i);
        aead_open(&msg_key[..], &wire[8..], &aad, self.0.n_maps)
    }
}

// ---- two-locks wrapper (Phase 8.4): chaos OUTER wall over a VETTED inner vault (port of twolock.py) ----
//
// THE SECURITY GOAL of the whole project. The chaos keystream is UNVETTED, so it is NEVER the only lock.
// We wrap the data in two independent locks, one inside the other:
//
//     plaintext --[ INNER vault: AES-256-GCM / ChaCha20-Poly1305 ]--> --[ OUTER wall: chaos AEAD ]--> wire
//
// The inner vault is a real, peer-reviewed cipher and is what ACTUALLY guarantees the data. The outer
// chaos AEAD is the exposed, sacrificial barrier an attacker hits first. Even a TOTAL chaos break leaves
// the attacker facing AES-256-GCM (~2^128), data intact — that is why an unvetted cipher is safe to ship
// HERE and nowhere else. Vetted INSIDE, chaos OUTSIDE: the lock the plaintext depends on must be the
// vetted one, and the unvetted experiment lives where attackers can batter it. (Full rationale: twolock.py.)
//
// KEY SEPARATION: the two locks never share a key. HKDF-SHA256 (vetted, RFC 5869, salt=None to match
// Python) splits the caller's master key into two independent 32-byte keys under distinct info labels —
// breaking the outer (chaos) key reveals nothing about the inner (vault) key.
//
// Wire format: the blob IS the outer chaos AEAD blob. What the chaos layer encrypts is the inner blob:
//     alg(1) || inner_nonce(12) || inner_ciphertext+tag(N)
// The alg byte rides INSIDE the authenticated+encrypted outer layer, so open is self-describing and an
// attacker can neither read nor change which inner cipher was used. The same aad binds BOTH locks.
//
// Like aead_seal, the two nonces (inner 12-byte, outer 16-byte) are the only nondeterminism; the Python
// shell randomizes them, the Rust core takes them explicitly so the caller owns randomness and the KAT
// can pin them. Both inner ciphers and HKDF are standard RustCrypto crates — only the OUTER wall is ours.

use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;

pub const INNER_NONCE_LEN: usize = 12; // 96-bit nonce for both AES-GCM and ChaCha20-Poly1305
const TWOLOCK_KEY_LEN: usize = 32; // AES-256 / ChaCha20 key, and the derived outer-wall key

/// Inner-cipher selector. Authenticated+encrypted inside the outer layer, so open is self-describing.
pub const TWOLOCK_AES: u8 = 0x01;
pub const TWOLOCK_CHACHA: u8 = 0x02;

const TWOLOCK_HKDF_INNER_INFO: &[u8] = b"chaos-pwlcm-v1|twolock|inner-vault|v1";
const TWOLOCK_HKDF_OUTER_INFO: &[u8] = b"chaos-pwlcm-v1|twolock|outer-wall|v1";

/// One HKDF-SHA256 derivation (salt=None -> a string of zeros, matching Python's `HKDF(salt=None)`).
/// The result is `Zeroizing`, so the derived key is wiped from memory when it drops.
fn hkdf_sha256_key(master_key: &[u8], info: &[u8]) -> Zeroizing<[u8; TWOLOCK_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = Zeroizing::new([0u8; TWOLOCK_KEY_LEN]);
    hk.expand(info, &mut okm[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Split the master key into (outer-wall key, inner-vault key). Distinct info labels domain-separate
/// them; HKDF's one-wayness means recovering one (e.g. by breaking chaos) does not leak the other.
fn twolock_derive_keys(
    master_key: &[u8],
) -> (Zeroizing<[u8; TWOLOCK_KEY_LEN]>, Zeroizing<[u8; TWOLOCK_KEY_LEN]>) {
    let k_outer = hkdf_sha256_key(master_key, TWOLOCK_HKDF_OUTER_INFO);
    let k_inner = hkdf_sha256_key(master_key, TWOLOCK_HKDF_INNER_INFO);
    (k_outer, k_inner)
}

/// Generic vetted-AEAD encrypt over RustCrypto's `aead` trait (works for AES-256-GCM and ChaCha20-
/// Poly1305 alike). Returns ciphertext||tag, or None if the key length is wrong.
fn vault_seal<C: Aead + KeyInit>(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = C::new_from_slice(key).ok()?;
    cipher
        .encrypt(GenericArray::from_slice(nonce), Payload { msg: pt, aad })
        .ok()
}

/// Generic vetted-AEAD decrypt: None on a bad tag (wrong key / tamper) or wrong key length.
fn vault_open<C: Aead + KeyInit>(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = C::new_from_slice(key).ok()?;
    cipher
        .decrypt(GenericArray::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

fn inner_vault_seal(alg: u8, key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    match alg {
        TWOLOCK_AES => vault_seal::<Aes256Gcm>(key, nonce, pt, aad),
        TWOLOCK_CHACHA => vault_seal::<ChaCha20Poly1305>(key, nonce, pt, aad),
        _ => None,
    }
}

fn inner_vault_open(alg: u8, key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    match alg {
        TWOLOCK_AES => vault_open::<Aes256Gcm>(key, nonce, ct, aad),
        TWOLOCK_CHACHA => vault_open::<ChaCha20Poly1305>(key, nonce, ct, aad),
        _ => None,
    }
}

/// Seal under two independent locks: the vetted inner vault, then the chaos outer wall (mirror of
/// seal_twolock). `inner_alg` selects the vault (TWOLOCK_AES / TWOLOCK_CHACHA). `aad` is bound to BOTH
/// locks. None if the inner cipher id is unknown. The two nonces are explicit (caller owns randomness).
pub fn twolock_seal(
    master_key: &[u8],
    outer_nonce: &[u8],
    inner_nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    inner_alg: u8,
    n_maps: usize,
) -> Option<Vec<u8>> {
    let (k_outer, k_inner) = twolock_derive_keys(master_key);
    // INNER vault: real, vetted AEAD with its own nonce.
    let inner_ct = inner_vault_seal(inner_alg, &k_inner[..], &inner_nonce[..INNER_NONCE_LEN], plaintext, aad)?;
    let mut inner_blob = Vec::with_capacity(1 + INNER_NONCE_LEN + inner_ct.len());
    inner_blob.push(inner_alg);
    inner_blob.extend_from_slice(&inner_nonce[..INNER_NONCE_LEN]);
    inner_blob.extend_from_slice(&inner_ct);
    // OUTER wall: the chaos AEAD wraps the whole inner blob (and binds the same aad again).
    Some(aead_seal(&k_outer[..], outer_nonce, &inner_blob, aad, n_maps))
}

/// Peel the chaos outer wall, then open the vetted inner vault (mirror of open_twolock). None if EITHER
/// lock rejects (wrong key or tamper at any layer); plaintext is NEVER returned in that case. The inner
/// cipher id is read from the authenticated inner blob, so the caller need not specify it.
pub fn twolock_open(master_key: &[u8], blob: &[u8], aad: &[u8], n_maps: usize) -> Option<Vec<u8>> {
    let (k_outer, k_inner) = twolock_derive_keys(master_key);
    // OUTER wall first: chaos AEAD verifies + decrypts; None on tamper / wrong outer key.
    let inner_blob = aead_open(&k_outer[..], blob, aad, n_maps)?;
    if inner_blob.len() < 1 + INNER_NONCE_LEN {
        return None;
    }
    let alg = inner_blob[0];
    let inner_nonce = &inner_blob[1..1 + INNER_NONCE_LEN];
    let inner_ct = &inner_blob[1 + INNER_NONCE_LEN..];
    // INNER vault: the lock that actually guarantees the data — stops an attacker even if chaos fell.
    inner_vault_open(alg, &k_inner[..], inner_nonce, inner_ct, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_seal_open_roundtrip_and_attacks() {
        let key = b"streaming key";
        let salt = b"sixteen-byte-slt"; // 16 bytes
        let aad = b"file.bin";
        let chunks: [&[u8]; 3] = [b"chunk one", b"chunk two is longer", b"three"];
        let blob = stream_seal(key, salt, &chunks, aad, DEFAULT_N_MAPS);
        let joined: Vec<u8> = chunks.concat();
        assert_eq!(stream_open(key, &blob, aad, DEFAULT_N_MAPS).as_deref(), Some(&joined[..]));

        // tamper a ciphertext byte
        let mut bad = blob.clone();
        bad[HEADER_LEN + FRAME_LEN_BYTES + 1] ^= 0x01;
        assert!(stream_open(key, &bad, aad, DEFAULT_N_MAPS).is_none());
        // wrong key / wrong aad
        assert!(stream_open(b"wrong", &blob, aad, DEFAULT_N_MAPS).is_none());
        assert!(stream_open(key, &blob, b"other", DEFAULT_N_MAPS).is_none());
        // truncate the final frame -> never see final
        let cut = HEADER_LEN
            + FRAME_LEN_BYTES
            + (1 + "chunk one".len() + TAG_LEN);
        assert!(stream_open(key, &blob[..cut], aad, DEFAULT_N_MAPS).is_none());
    }

    #[test]
    fn stream_empty_roundtrips() {
        let key = b"k";
        let salt = b"0123456789abcdef";
        let blob = stream_seal(key, salt, &[], b"", DEFAULT_N_MAPS);
        assert_eq!(stream_open(key, &blob, b"", DEFAULT_N_MAPS).as_deref(), Some(&b""[..]));
    }

    #[test]
    fn aead_seal_open_roundtrip() {
        let key = b"a shared secret key";
        let nonce = b"sixteen-byte-non"; // 16 bytes
        let aad = b"context";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let blob = aead_seal(key, nonce, pt, aad, DEFAULT_N_MAPS);
        assert_eq!(aead_open(key, &blob, aad, DEFAULT_N_MAPS).as_deref(), Some(&pt[..]));
    }

    #[test]
    fn aead_open_rejects_tamper_wrong_key_and_aad() {
        let key = b"a shared secret key";
        let nonce = b"sixteen-byte-non";
        let aad = b"context";
        let pt = b"secret payload";
        let blob = aead_seal(key, nonce, pt, aad, DEFAULT_N_MAPS);
        // tamper a ciphertext byte
        let mut bad = blob.clone();
        let i = NONCE_LEN + COMMIT_LEN + 1;
        bad[i] ^= 0x01;
        assert!(aead_open(key, &bad, aad, DEFAULT_N_MAPS).is_none());
        // wrong key
        assert!(aead_open(b"the wrong key", &blob, aad, DEFAULT_N_MAPS).is_none());
        // wrong aad
        assert!(aead_open(key, &blob, b"other", DEFAULT_N_MAPS).is_none());
        // truncation
        assert!(aead_open(key, &blob[..blob.len() - 1], aad, DEFAULT_N_MAPS).is_none());
    }

    #[test]
    fn ratchet_aead_session_roundtrip_and_forward_secrecy() {
        let master = b"a forward-secret session master key";
        let nonce = b"session-nonce-001";
        let aad = b"channel-7";
        let convo: [&[u8]; 3] = [b"hello", b"the package is in locker 12", b"burn after reading"];
        // deterministic inner nonces (the caller owns randomness in the Rust core)
        let inonces: [&[u8]; 3] = [b"inner-nonce-aaa0", b"inner-nonce-aaa1", b"inner-nonce-aaa2"];

        let mut tx = RatchetAeadSender::new(master, nonce, aad, DEFAULT_N_MAPS);
        let wires: Vec<Vec<u8>> = convo
            .iter()
            .zip(inonces.iter())
            .map(|(m, n)| tx.seal(n, m))
            .collect();

        // in-order receiver recovers every message
        let mut rx = RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS);
        for (w, m) in wires.iter().zip(convo.iter()) {
            assert_eq!(rx.open(w).as_deref(), Some(*m));
        }

        // forward secrecy: a receiver poised past message 0/1 cannot reopen them (key burned)
        let mut late = RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS);
        assert!(late.open(&wires[0]).is_some());
        assert!(late.open(&wires[1]).is_some()); // now poised at index 2
        assert!(late.open(&wires[0]).is_none(), "past message reopened — forward secrecy broken");
        assert!(late.open(&wires[1]).is_none());

        // gap tolerated: a fresh receiver can jump to message 2 (burns 0,1) but then can't go back
        let mut skip = RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS);
        assert_eq!(skip.open(&wires[2]).as_deref(), Some(convo[2]));
        assert!(skip.open(&wires[0]).is_none());
    }

    #[test]
    fn ratchet_aead_rejects_tamper_wrong_key_and_index() {
        let master = b"session master";
        let nonce = b"sess-nonce";
        let aad = b"";
        let inonce = b"sixteen-byte-non";
        let pt = b"secret session payload";

        let mut tx = RatchetAeadSender::new(master, nonce, aad, DEFAULT_N_MAPS);
        let wire = tx.seal(inonce, pt);

        // clean open works
        assert_eq!(
            RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS).open(&wire).as_deref(),
            Some(&pt[..])
        );
        // tamper an inner ciphertext byte
        let mut bad = wire.clone();
        bad[8 + NONCE_LEN + COMMIT_LEN + 1] ^= 0x01;
        assert!(RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS).open(&bad).is_none());
        // wrong master key
        assert!(RatchetAeadReceiver::new(b"wrong", nonce, aad, DEFAULT_N_MAPS).open(&wire).is_none());
        // wrong session nonce
        assert!(RatchetAeadReceiver::new(master, b"other", aad, DEFAULT_N_MAPS).open(&wire).is_none());
        // bump the wire index -> inner aad mismatch -> open fails
        let mut idx = wire.clone();
        idx[7] ^= 0x01;
        assert!(RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS).open(&idx).is_none());
    }

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

    #[test]
    fn twolock_roundtrip_both_inner_ciphers() {
        let master = b"two-locks master key";
        let outer_nonce = b"outer-nonce-16by"; // 16 bytes
        let inner_nonce = b"inner-nonce1"; // 12 bytes
        let aad = b"context";
        let pt = b"vault the secret behind two independent locks";
        for alg in [TWOLOCK_AES, TWOLOCK_CHACHA] {
            let blob =
                twolock_seal(master, outer_nonce, inner_nonce, pt, aad, alg, DEFAULT_N_MAPS).unwrap();
            let got = twolock_open(master, &blob, aad, DEFAULT_N_MAPS).unwrap();
            assert_eq!(got, pt, "two-locks round trip failed for inner alg {alg:#x}");
        }
    }

    #[test]
    fn twolock_rejects_tamper_wrong_key_and_wrong_aad() {
        let master = b"two-locks master key";
        let outer_nonce = b"outer-nonce-16by";
        let inner_nonce = b"inner-nonce1";
        let aad = b"context";
        let pt = b"defense in depth";
        let blob =
            twolock_seal(master, outer_nonce, inner_nonce, pt, aad, TWOLOCK_AES, DEFAULT_N_MAPS)
                .unwrap();

        // Wrong master key -> the outer wall rejects (its derived key is different).
        assert!(twolock_open(b"the wrong master key", &blob, aad, DEFAULT_N_MAPS).is_none());
        // Wrong aad -> the outer wall's MAC/commitment rejects.
        assert!(twolock_open(master, &blob, b"other aad", DEFAULT_N_MAPS).is_none());
        // Flip one outer-ciphertext byte (past nonce + commitment) -> rejected, no plaintext.
        let mut bad = blob.clone();
        bad[NONCE_LEN + COMMIT_LEN + 1] ^= 0x01;
        assert!(twolock_open(master, &bad, aad, DEFAULT_N_MAPS).is_none());
    }

    #[test]
    fn twolock_key_separation_outer_key_does_not_open_inner() {
        // The whole guarantee: even if an attacker fully breaks chaos and recovers the OUTER blob's
        // plaintext (the inner blob), the inner vault key is independent — so they cannot open it.
        let master = b"two-locks master key";
        let (k_outer, k_inner) = twolock_derive_keys(master);
        assert_ne!(&k_outer[..], &k_inner[..], "the two derived keys must differ");

        // Peel the outer wall ourselves (simulating a total chaos break) to get the inner blob...
        let blob = twolock_seal(master, b"outer-nonce-16by", b"inner-nonce1", b"top secret", b"a",
                                TWOLOCK_AES, DEFAULT_N_MAPS).unwrap();
        let inner_blob = aead_open(&k_outer[..], &blob, b"a", DEFAULT_N_MAPS).unwrap();
        let alg = inner_blob[0];
        let nonce = &inner_blob[1..1 + INNER_NONCE_LEN];
        let ct = &inner_blob[1 + INNER_NONCE_LEN..];
        // ...the inner vault opens with the inner key, but NOT with the (exposed) outer key.
        assert!(inner_vault_open(alg, &k_inner[..], nonce, ct, b"a").is_some());
        assert!(inner_vault_open(alg, &k_outer[..], nonce, ct, b"a").is_none());
    }
}
