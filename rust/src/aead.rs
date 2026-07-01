//! Committing AEAD shell — the SIMPLE, SAFE interface over the chaos keystream.
//!
//! Port of aead.py + commit.py (Phase 8.1). The chaos keystream is the (UNVETTED)
//! bulk cipher; integrity and key-commitment ride vetted HMAC-SHA256.
//!
//! Wire format: nonce(16) || commit(32) || ciphertext(N) || tag(32)
//!
//! STILL UNVETTED. See REPORT.md.

use crate::utils::{ct_eq, hmac_sha256, hmac_sha256_multi};
use crate::multimap::MultiMapEngine;

pub const NONCE_LEN: usize = 16;
pub const COMMIT_LEN: usize = 32;
pub const TAG_LEN: usize = 32;

const COMMIT_KEY_INFO: &[u8] = b"chaos-pwlcm-v1|commit-key|v1";
const MAC_INFO: &[u8] = b"chaos-pwlcm-v1|mac-key";

/// CMT-4 key-commitment binding the master key to (salt, aad). Mirror of commit.py.
pub fn key_commitment(master_key: &[u8], salt: &[u8], aad: &[u8]) -> [u8; 32] {
    let k_c = hmac_sha256(master_key, COMMIT_KEY_INFO);
    let alen = (aad.len() as u64).to_be_bytes();
    hmac_sha256_multi(&k_c, &[salt, &alen, aad])
}

/// Encrypt-then-MAC tag over nonce + commitment + length-prefixed aad + ciphertext.
fn aead_tag(master_key: &[u8], nonce: &[u8], commit: &[u8], aad: &[u8], ct: &[u8]) -> [u8; 32] {
    let mac_key = hmac_sha256(master_key, MAC_INFO);
    let alen = (aad.len() as u64).to_be_bytes();
    hmac_sha256_multi(&mac_key, &[nonce, commit, &alen, aad, ct])
}

/// Seal: nonce || commit || (plaintext XOR keystream) || tag. Deterministic in the given nonce.
pub fn aead_seal(
    master_key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    n_maps: usize,
) -> Vec<u8> {
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
pub fn aead_open(
    master_key: &[u8],
    blob: &[u8],
    aad: &[u8],
    n_maps: usize,
) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_N_MAPS;

    #[test]
    fn aead_seal_open_roundtrip() {
        let key = b"a shared secret key";
        let nonce = b"sixteen-byte-non";
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
        let mut bad = blob.clone();
        let i = NONCE_LEN + COMMIT_LEN + 1;
        bad[i] ^= 0x01;
        assert!(aead_open(key, &bad, aad, DEFAULT_N_MAPS).is_none());
        assert!(aead_open(b"the wrong key", &blob, aad, DEFAULT_N_MAPS).is_none());
        assert!(aead_open(key, &blob, b"other", DEFAULT_N_MAPS).is_none());
        assert!(aead_open(key, &blob[..blob.len() - 1], aad, DEFAULT_N_MAPS).is_none());
    }
}
