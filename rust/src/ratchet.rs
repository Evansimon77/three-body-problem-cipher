//! Forward-secret, unbounded keystream via a one-way HMAC-SHA256 key chain.
//!
//! Port of ratchet.py. Re-keys every epoch_bytes (default 64 KiB) and BURNS
//! the old key: a live capture reveals only the current epoch onward, never
//! earlier. Also dissolves the per-map period limit — each epoch is a fresh
//! ~2^252 orbit.
//!
//! STILL UNVETTED. See REPORT.md.

use zeroize::{Zeroize, Zeroizing};

use crate::utils::{cat, hmac_sha256};
use crate::multimap::MultiMapEngine;

/// Domain-separation tag for the ratchet's key chain (must match ratchet.py `_V` byte-for-byte).
const RATCHET_V: &[u8] = b"chaos-ratchet-v1|";

/// Auto-rekey: a one-way key chain that re-keys every `epoch_bytes` and burns the old key,
/// giving forward secrecy and an effectively unbounded stream. Drop-in for `MultiMapEngine`.
pub struct RatchetEngine {
    nonce: Vec<u8>,
    epoch_bytes: usize,
    n_maps: usize,
    chain_key: Zeroizing<[u8; 32]>,
    epoch_index: u64,
    engine: MultiMapEngine,
    remaining: usize,
}

impl RatchetEngine {
    pub fn new(master_key: &[u8], nonce: &[u8], epoch_bytes: usize, n_maps: usize) -> Self {
        assert!(epoch_bytes >= 1, "epoch_bytes must be >= 1");
        let mut k0 = hmac_sha256(master_key, &cat(&[RATCHET_V, b"init|", nonce]));
        let (engine, next_chain) = Self::derive_epoch(&k0, nonce, n_maps, 0);
        k0.zeroize();
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
        epoch_key.zeroize();
        (engine, next_chain)
    }

    /// Step the chain into the next epoch: derive a fresh engine + chain key, then BURN K_i in place.
    fn advance(&mut self) {
        let (engine, mut next_chain) =
            Self::derive_epoch(&self.chain_key, &self.nonce, self.n_maps, self.epoch_index);
        self.engine = engine;
        self.chain_key.zeroize();
        self.chain_key.copy_from_slice(&next_chain);
        next_chain.zeroize();
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
