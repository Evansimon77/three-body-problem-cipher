//! Multi-body keystream engine: N INDEPENDENT PWLCM maps, XOR-combined.
//!
//! Port of multimap.py. Each sub-map gets an unrelated cryptographic seed via
//! domain-separated KDF. Default is 4 independent maps — the multi-body design
//! that defeats the single-map state-recovery attack.
//!
//! STILL UNVETTED — this defeats the naive per-map recovery; it is not a proof
//! of security. See REPORT.md.

use crate::engine::{ChaosEngine, OUTPUT_BYTES_PER_STEP};
use crate::utils::{derive_seed_control, kdf_hash};

/// The shipped keystream: N INDEPENDENT PWLCM engines XOR-combined.
pub struct MultiMapEngine {
    engines: Vec<ChaosEngine>,
    buf: [u8; OUTPUT_BYTES_PER_STEP],
    buf_i: usize,
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
            buf_i: OUTPUT_BYTES_PER_STEP,
        }
    }

    /// Step EVERY map once and XOR their per-step blocks into one combined block.
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

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let ks = self.keystream(data.len());
        data.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect()
    }
}
