//! Two-locks wrapper — chaos OUTER wall over a VETTED inner vault (Phase 8.4).
//!
//! Port of twolock.py. THE SECURITY GOAL of the whole project. The chaos keystream
//! is UNVETTED, so it is NEVER the only lock. We wrap the data in two independent
//! locks, one inside the other:
//!
//!    plaintext --[ INNER vault: AES-256-GCM / ChaCha20-Poly1305 ]-->
//!              --[ OUTER wall: chaos AEAD ]--> wire
//!
//! Even a TOTAL chaos break leaves the attacker facing AES-256-GCM (~2^128),
//! data intact. That is why an unvetted cipher is safe to ship HERE and nowhere else.
//!
//! STILL UNVETTED (the chaos half). But the data's security rests on the vetted half.

use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead::{aead_open, aead_seal};

pub const INNER_NONCE_LEN: usize = 12;
const TWOLOCK_KEY_LEN: usize = 32;

/// Inner-cipher selector. Authenticated+encrypted inside the outer layer.
pub const TWOLOCK_AES: u8 = 0x01;
pub const TWOLOCK_CHACHA: u8 = 0x02;

const TWOLOCK_HKDF_INNER_INFO: &[u8] = b"chaos-pwlcm-v1|twolock|inner-vault|v1";
const TWOLOCK_HKDF_OUTER_INFO: &[u8] = b"chaos-pwlcm-v1|twolock|outer-wall|v1";

/// One HKDF-SHA256 derivation (salt=None, matching Python's HKDF).
fn hkdf_sha256_key(master_key: &[u8], info: &[u8]) -> Zeroizing<[u8; TWOLOCK_KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = Zeroizing::new([0u8; TWOLOCK_KEY_LEN]);
    hk.expand(info, &mut okm[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Split the master key into (outer-wall key, inner-vault key).
fn twolock_derive_keys(
    master_key: &[u8],
) -> (
    Zeroizing<[u8; TWOLOCK_KEY_LEN]>,
    Zeroizing<[u8; TWOLOCK_KEY_LEN]>,
) {
    let k_outer = hkdf_sha256_key(master_key, TWOLOCK_HKDF_OUTER_INFO);
    let k_inner = hkdf_sha256_key(master_key, TWOLOCK_HKDF_INNER_INFO);
    (k_outer, k_inner)
}

/// Generic vetted-AEAD encrypt.
fn vault_seal<C: Aead + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    pt: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let cipher = C::new_from_slice(key).ok()?;
    cipher
        .encrypt(GenericArray::from_slice(nonce), Payload { msg: pt, aad })
        .ok()
}

/// Generic vetted-AEAD decrypt.
fn vault_open<C: Aead + KeyInit>(
    key: &[u8],
    nonce: &[u8],
    ct: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let cipher = C::new_from_slice(key).ok()?;
    cipher
        .decrypt(GenericArray::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

fn inner_vault_seal(
    alg: u8,
    key: &[u8],
    nonce: &[u8],
    pt: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    match alg {
        TWOLOCK_AES => vault_seal::<Aes256Gcm>(key, nonce, pt, aad),
        TWOLOCK_CHACHA => vault_seal::<ChaCha20Poly1305>(key, nonce, pt, aad),
        _ => None,
    }
}

fn inner_vault_open(
    alg: u8,
    key: &[u8],
    nonce: &[u8],
    ct: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    match alg {
        TWOLOCK_AES => vault_open::<Aes256Gcm>(key, nonce, ct, aad),
        TWOLOCK_CHACHA => vault_open::<ChaCha20Poly1305>(key, nonce, ct, aad),
        _ => None,
    }
}

/// Seal under two independent locks: the vetted inner vault, then the chaos outer wall.
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
    let inner_ct =
        inner_vault_seal(inner_alg, &k_inner[..], &inner_nonce[..INNER_NONCE_LEN], plaintext, aad)?;
    let mut inner_blob = Vec::with_capacity(1 + INNER_NONCE_LEN + inner_ct.len());
    inner_blob.push(inner_alg);
    inner_blob.extend_from_slice(&inner_nonce[..INNER_NONCE_LEN]);
    inner_blob.extend_from_slice(&inner_ct);
    Some(aead_seal(
        &k_outer[..],
        outer_nonce,
        &inner_blob,
        aad,
        n_maps,
    ))
}

/// Peel the chaos outer wall, then open the vetted inner vault.
pub fn twolock_open(
    master_key: &[u8],
    blob: &[u8],
    aad: &[u8],
    n_maps: usize,
) -> Option<Vec<u8>> {
    let (k_outer, k_inner) = twolock_derive_keys(master_key);
    let inner_blob = aead_open(&k_outer[..], blob, aad, n_maps)?;
    if inner_blob.len() < 1 + INNER_NONCE_LEN {
        return None;
    }
    let alg = inner_blob[0];
    let inner_nonce = &inner_blob[1..1 + INNER_NONCE_LEN];
    let inner_ct = &inner_blob[1 + INNER_NONCE_LEN..];
    inner_vault_open(alg, &k_inner[..], inner_nonce, inner_ct, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::aead_open as chaos_aead_open;
    use crate::constants::DEFAULT_N_MAPS;

    #[test]
    fn twolock_roundtrip_both_inner_ciphers() {
        let master = b"two-locks master key";
        let outer_nonce = b"outer-nonce-16by";
        let inner_nonce = b"inner-nonce1";
        let aad = b"context";
        let pt = b"vault the secret behind two independent locks";
        for alg in [TWOLOCK_AES, TWOLOCK_CHACHA] {
            let blob = twolock_seal(master, outer_nonce, inner_nonce, pt, aad, alg, DEFAULT_N_MAPS)
                .unwrap();
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

        assert!(twolock_open(b"the wrong master key", &blob, aad, DEFAULT_N_MAPS).is_none());
        assert!(twolock_open(master, &blob, b"other aad", DEFAULT_N_MAPS).is_none());
        let mut bad = blob.clone();
        bad[crate::aead::NONCE_LEN + crate::aead::COMMIT_LEN + 1] ^= 0x01;
        assert!(twolock_open(master, &bad, aad, DEFAULT_N_MAPS).is_none());
    }

    #[test]
    fn twolock_key_separation_outer_key_does_not_open_inner() {
        let master = b"two-locks master key";
        let (k_outer, k_inner) = twolock_derive_keys(master);
        assert_ne!(&k_outer[..], &k_inner[..]);

        let blob = twolock_seal(
            master,
            b"outer-nonce-16by",
            b"inner-nonce1",
            b"top secret",
            b"a",
            TWOLOCK_AES,
            DEFAULT_N_MAPS,
        )
        .unwrap();
        let inner_blob = chaos_aead_open(&k_outer[..], &blob, b"a", DEFAULT_N_MAPS).unwrap();
        let alg = inner_blob[0];
        let nonce = &inner_blob[1..1 + INNER_NONCE_LEN];
        let ct = &inner_blob[1 + INNER_NONCE_LEN..];
        assert!(inner_vault_open(alg, &k_inner[..], nonce, ct, b"a").is_some());
        assert!(inner_vault_open(alg, &k_outer[..], nonce, ct, b"a").is_none());
    }
}
