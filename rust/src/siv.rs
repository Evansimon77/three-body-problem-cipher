//! SIV "seatbelt" — nonce-MISUSE-resistant AEAD over the chaos core.
//!
//! Port of siv.py. The IV is synthesised from the message itself (HMAC of aad + plaintext),
//! so there is NO nonce for the caller to get wrong. Two different messages always get
//! different keystreams; two identical messages produce identical output (deterministic
//! encryption — the minimum leak for any scheme that needs no nonce).
//!
//! Wire format: commit(32) || siv(32) || ciphertext(N)
//!
//! STILL UNVETTED. See REPORT.md.

use crate::aead::{key_commitment, COMMIT_LEN};
use crate::multimap::MultiMapEngine;
use crate::utils::{ct_eq, hmac_sha256, hmac_sha256_multi};

/// HMAC-SHA256 output length — serves as BOTH IV and auth tag.
pub const SIV_LEN: usize = 32;

const _SIV_INFO: &[u8] = b"chaos-pwlcm-v1|siv-key";

fn siv_key(master_key: &[u8]) -> [u8; 32] {
    hmac_sha256(master_key, _SIV_INFO)
}

fn synthesise_iv(master_key: &[u8], aad: &[u8], plaintext: &[u8]) -> [u8; 32] {
    let sk = siv_key(master_key);
    // Length-prefix aad so the (aad | plaintext) boundary cannot be slid.
    hmac_sha256_multi(&sk, &[&(aad.len() as u64).to_be_bytes(), aad, plaintext])
}

/// Encrypt + authenticate with NO caller-supplied nonce.
///
/// Returns `commit || siv || ciphertext`. Two DIFFERENT messages always get unrelated
/// keystreams; two IDENTICAL messages seal to identical output (deterministic encryption).
pub fn siv_seal(
    master_key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    n_maps: usize,
) -> Vec<u8> {
    let siv = synthesise_iv(master_key, aad, plaintext);
    let ciphertext = MultiMapEngine::new(master_key, &siv, n_maps).encrypt(plaintext);
    let commit = key_commitment(master_key, &siv, aad);
    let mut blob = Vec::with_capacity(COMMIT_LEN + SIV_LEN + ciphertext.len());
    blob.extend_from_slice(&commit);
    blob.extend_from_slice(&siv);
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Verify + decrypt. Returns None on any mismatch — wrong key or tampering.
///
/// Re-derives the SIV from the recovered plaintext and compares in constant time.
/// The plaintext is NEVER returned if verification fails.
pub fn siv_open(
    master_key: &[u8],
    blob: &[u8],
    aad: &[u8],
    n_maps: usize,
) -> Option<Vec<u8>> {
    if blob.len() < COMMIT_LEN + SIV_LEN {
        return None;
    }
    let commit = &blob[..COMMIT_LEN];
    let siv = &blob[COMMIT_LEN..COMMIT_LEN + SIV_LEN];
    let ciphertext = &blob[COMMIT_LEN + SIV_LEN..];

    // Key-commitment: reject a key that doesn't match BEFORE touching ciphertext.
    let expected_commit = key_commitment(master_key, siv, aad);
    if !ct_eq(commit, &expected_commit) {
        return None;
    }

    let plaintext = MultiMapEngine::new(master_key, siv, n_maps).encrypt(ciphertext);
    let expected = synthesise_iv(master_key, aad, &plaintext);
    if !ct_eq(&expected, siv) {
        return None;
    }
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_N_MAPS;

    #[test]
    fn siv_seal_open_roundtrip() {
        let key = b"my shared secret key (any bytes)";
        let msg = b"Attack at dawn. Wire $40,000 by Friday.";
        let blob = siv_seal(key, msg, b"", DEFAULT_N_MAPS);
        let pt = siv_open(key, &blob, b"", DEFAULT_N_MAPS).expect("roundtrip failed");
        assert_eq!(pt, msg);
    }

    #[test]
    fn siv_deterministic_two_seals_identical() {
        let key = b"deterministic-test-key";
        let msg = b"same plaintext sealed twice";
        let a = siv_seal(key, msg, b"", DEFAULT_N_MAPS);
        let b = siv_seal(key, msg, b"", DEFAULT_N_MAPS);
        assert_eq!(a, b);
    }

    #[test]
    fn siv_different_messages_different_output() {
        let key = b"uniqueness-test-key";
        let a = siv_seal(key, b"AAAAAAAAAAAAAAAA", b"", DEFAULT_N_MAPS);
        let b = siv_seal(key, b"AAAAAAAAAAAAAAAB", b"", DEFAULT_N_MAPS);
        assert_ne!(a, b);
    }

    #[test]
    fn siv_rejects_tamper_wrong_key_and_aad() {
        let key = b"a very good shared key";
        let msg = b"confidential message";
        let blob = siv_seal(key, msg, b"", DEFAULT_N_MAPS);

        // Tamper
        let mut bad = blob.clone();
        bad[COMMIT_LEN + SIV_LEN] ^= 0x01;
        assert!(siv_open(key, &bad, b"", DEFAULT_N_MAPS).is_none());

        // Wrong key
        assert!(siv_open(b"the wrong key................", &blob, b"", DEFAULT_N_MAPS).is_none());

        // Wrong aad
        assert!(siv_open(key, &blob, b"wrong aad", DEFAULT_N_MAPS).is_none());
    }

    #[test]
    fn siv_too_short() {
        assert!(siv_open(b"key", &[0u8; 16], b"", DEFAULT_N_MAPS).is_none());
    }
}
