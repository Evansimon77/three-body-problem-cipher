//! Streaming AEAD — the STREAM construction (Phase 8.2).
//!
//! Port of streaming.py. Encrypt a big payload chunk-by-chunk. Each chunk's HMAC
//! binds its index + a `final` flag, so reorder / drop / duplicate / truncate are
//! all caught on top of tamper. The header carries a key-commitment.
//!
//! Wire format (self-delimiting one-shot form):
//!   header : salt(16) || commit(32)
//!   frame  : framelen(4, BE) || flags(1) || ciphertext(N) || tag(32)
//!
//! STILL UNVETTED. See REPORT.md.

use crate::aead::{key_commitment, COMMIT_LEN, TAG_LEN};
use crate::utils::{ct_eq, hmac_sha256, hmac_sha256_multi};
use crate::multimap::MultiMapEngine;

pub const SALT_LEN: usize = 16;
pub const HEADER_LEN: usize = SALT_LEN + COMMIT_LEN;
const STREAM_MAC_INFO: &[u8] = b"chaos-pwlcm-v1|stream-mac-key";
const FINAL_FLAG: u8 = 0x01;
const FRAME_LEN_BYTES: usize = 4;

fn stream_mac_key(master_key: &[u8]) -> [u8; 32] {
    hmac_sha256(master_key, STREAM_MAC_INFO)
}

fn chunk_tag(
    mac_key: &[u8],
    salt: &[u8],
    index: u64,
    flags: u8,
    aad: &[u8],
    ct: &[u8],
) -> [u8; 32] {
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

/// Seal a list of chunks into one self-delimiting blob. Deterministic in the given salt.
pub fn stream_seal(
    master_key: &[u8],
    salt: &[u8],
    chunks: &[&[u8]],
    aad: &[u8],
    n_maps: usize,
) -> Vec<u8> {
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

/// Verify + decrypt a blob made by `stream_seal`. None on any manipulation.
pub fn stream_open(
    master_key: &[u8],
    blob: &[u8],
    aad: &[u8],
    n_maps: usize,
) -> Option<Vec<u8>> {
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
        let flen =
            u32::from_be_bytes(blob[pos..pos + FRAME_LEN_BYTES].try_into().ok()?) as usize;
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
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_N_MAPS;

    #[test]
    fn stream_seal_open_roundtrip_and_attacks() {
        let key = b"streaming key";
        let salt = b"sixteen-byte-slt";
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
        // truncate the final frame
        let cut = HEADER_LEN + FRAME_LEN_BYTES + (1 + "chunk one".len() + TAG_LEN);
        assert!(stream_open(key, &blob[..cut], aad, DEFAULT_N_MAPS).is_none());
    }

    #[test]
    fn stream_empty_roundtrips() {
        let key = b"k";
        let salt = b"0123456789abcdef";
        let blob = stream_seal(key, salt, &[], b"", DEFAULT_N_MAPS);
        assert_eq!(stream_open(key, &blob, b"", DEFAULT_N_MAPS).as_deref(), Some(&b""[..]));
    }
}
