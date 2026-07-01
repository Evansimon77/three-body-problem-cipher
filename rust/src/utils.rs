//! Shared cryptographic utility helpers — one home, used across every module.
//!
//! These were previously mixed into engine.rs (the chaos core) because the engine
//! was the first file written. They are not engine-specific: they are the communal
//! toolbox for constant-time comparison, HMAC operations, and KDF building blocks.

use hmac::{Hmac, Mac};
use ruint::aliases::U256;
use sha2::{Digest, Sha512};

pub type HmacSha256 = Hmac<sha2::Sha256>;

use crate::engine::{HALF, M, u};

#[inline]
fn lo128(x: U256) -> u128 {
    let l = x.as_limbs();
    (l[0] as u128) | ((l[1] as u128) << 64)
}

/// SHA-512 over `prefix [|| index_be(2)] || master_key || b"|" || nonce`.
pub(crate) fn kdf_hash(
    prefix: &[u8],
    index: Option<u16>,
    master_key: &[u8],
    nonce: &[u8],
) -> [u8; 64] {
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

/// Parse h[0:24] and h[24:48] as 192-bit big-endian integers, reduced for the engine.
pub(crate) fn derive_seed_control(h: &[u8; 64]) -> (u128, u128) {
    let seed = lo128(U256::from_be_slice(&h[0..24]) % u(M));
    let control = lo128(U256::from_be_slice(&h[24..48]) % u(HALF));
    (seed, control)
}

/// One-way HMAC-SHA256(key, label) -> 32 bytes.
pub(crate) fn hmac_sha256(key: &[u8], label: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

/// Concatenate byte slices into a fresh `Vec` (label building only — never in hot loop).
pub(crate) fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

/// Constant-time byte equality — no early-out, no timing leak.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-SHA256 over several parts in order (incremental, no intermediate concat).
pub(crate) fn hmac_sha256_multi(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}
