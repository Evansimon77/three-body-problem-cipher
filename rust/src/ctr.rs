//! Seekable counter mode — random-access encryption over the multi-map chaos core.
//!
//! Port of ctr.py. The keystream is divided into fixed-size blocks; each block is
//! independently keyed from (master_key, nonce, block_index) via a domain-separated
//! KDF. To read any offset you derive ONE block regardless of how far in it is —
//! O(1) random access instead of serial generation.
//!
//! STILL UNVETTED. See REPORT.md.

use crate::engine::ChaosEngine;

/// Keystream bytes per counter block. Mirrors ctr.py BLOCK_SIZE — balances
/// per-block KDF overhead vs seek granularity.
pub const BLOCK_SIZE: usize = 64;

const CTR_PREFIX: &[u8] = b"chaos-pwlcm-v1|ctr|";

pub struct SeekableCtr {
    master_key: Vec<u8>,
    nonce: Vec<u8>,
    n_maps: usize,
}

impl SeekableCtr {
    pub fn new(master_key: &[u8], nonce: &[u8], n_maps: usize) -> Self {
        if n_maps < 1 {
            panic!("n_maps must be >= 1");
        }
        SeekableCtr {
            master_key: master_key.to_vec(),
            nonce: nonce.to_vec(),
            n_maps,
        }
    }

    fn block_engine(&self, block_index: u64, map_index: u16) -> ChaosEngine {
        // CTR's KDF is unique: two counters folded in instead of a single Option<u16> index.
        // We hand-build the hash since kdf_hash only takes one optional index.
        use ruint::aliases::U256;
        use sha2::{Digest, Sha512};
        use crate::engine::{u, lo128, HALF, M};

        let mut hasher = Sha512::new();
        hasher.update(CTR_PREFIX);
        hasher.update(block_index.to_be_bytes());
        hasher.update(b"|");
        hasher.update(map_index.to_be_bytes());
        hasher.update(b"|");
        hasher.update(&self.master_key);
        hasher.update(b"|");
        hasher.update(&self.nonce);
        let h: [u8; 64] = hasher.finalize().into();
        let seed = lo128(U256::from_be_slice(&h[0..24]) % u(M));
        let control = lo128(U256::from_be_slice(&h[24..48]) % u(HALF));
        ChaosEngine::new(seed, control, 0)
    }

    fn block_keystream(&self, block_index: u64) -> Vec<u8> {
        // N independent maps XOR-combined per block, matching Python's _block_keystream.
        let mut engines: Vec<ChaosEngine> = (0..self.n_maps)
            .map(|i| self.block_engine(block_index, i as u16))
            .collect();
        let mut out = Vec::with_capacity(BLOCK_SIZE);
        for _ in 0..BLOCK_SIZE {
            let mut b: u8 = 0;
            for eng in &mut engines {
                b ^= eng.next_byte();
            }
            out.push(b);
        }
        out
    }

    /// Return `n` keystream bytes starting at absolute byte `offset`. Only the blocks
    /// covering [offset, offset+n) are derived; earlier blocks are skipped entirely.
    pub fn keystream(&mut self, n: usize, offset: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut pos = offset;
        while out.len() < n {
            let block_index = (pos / BLOCK_SIZE) as u64;
            let within = pos % BLOCK_SIZE;
            let block = self.block_keystream(block_index);
            let chunk = &block[within..];
            out.extend_from_slice(chunk);
            pos += chunk.len();
        }
        out.truncate(n);
        out
    }

    /// XOR `data` with the keystream starting at `offset`.
    pub fn encrypt(&mut self, data: &[u8], offset: usize) -> Vec<u8> {
        let ks = self.keystream(data.len(), offset);
        data.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_N_MAPS;

    #[test]
    fn ctr_determinism_two_instances_agree() {
        let key = b"my shared secret key";
        let nonce = b"unique-nonce-001";
        let a = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).keystream(16, 0);
        let b = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).keystream(16, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn ctr_seekability_window_matches_full_stream() {
        let key = b"seek-test-key";
        let nonce = b"seek-test-nonce";
        let full = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).keystream(300, 0);
        let window = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).keystream(20, 137);
        assert_eq!(window, full[137..157]);
    }

    #[test]
    fn ctr_offset_roundtrip() {
        let key = b"roundtrip-key";
        let nonce = b"roundtrip-nonce";
        let msg = b"the middle of a large file, decrypted without reading the start.";
        let ct = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).encrypt(msg, 1000);
        let pt = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).encrypt(&ct, 1000);
        assert_eq!(pt, msg);
    }

    #[test]
    fn ctr_different_offsets_different_keystream() {
        let key = b"offset-test-key";
        let nonce = b"offset-test-nonce";
        let ks0 = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).keystream(16, 0);
        let ks1 = SeekableCtr::new(key, nonce, DEFAULT_N_MAPS).keystream(16, 1);
        assert_ne!(ks0, ks1);
    }
}
