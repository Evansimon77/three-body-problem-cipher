//! Ratchet session AEAD — forward-secret SESSION over the committing AEAD (Phase 8.3).
//!
//! Port of ratchet_aead.py. A session where each message gets its OWN key from
//! a one-way HMAC-SHA256 chain; the link that made a key is burned after use.
//! Each message is sealed with the ordinary committing AEAD, inheriting
//! confidentiality + integrity + key-commitment for free.
//!
//! Wire format: index(8,BE) || aead_seal(msg_key_i, inner_nonce_i, plaintext, bind_aad)
//!
//! STILL UNVETTED. See REPORT.md.

use zeroize::{Zeroize, Zeroizing};

use crate::aead::{aead_open, aead_seal};
use crate::utils::{cat, hmac_sha256};

/// Domain-separation tag for the session-AEAD chain.
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

/// Authenticate the message index inside the inner AEAD: length-prefix the aad, then append the index.
fn ra_bind_aad(aad: &[u8], index: u64) -> Vec<u8> {
    let alen = (aad.len() as u64).to_be_bytes();
    cat(&[&alen, aad, &index.to_be_bytes()])
}

/// Shared chain state for a forward-secret session. Sender and receiver each hold one.
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

    /// Advance one link: return (this index, its message key) and BURN the consumed chain link.
    fn step(&mut self) -> (u64, Zeroizing<[u8; 32]>) {
        let i = self.index;
        let (msg_key, mut next_chain) = ra_derive(&self.chain, i);
        self.chain.zeroize();
        self.chain.copy_from_slice(&next_chain);
        next_chain.zeroize();
        self.index += 1;
        (i, Zeroizing::new(msg_key))
    }
}

/// Seal a sequence of messages with per-message forward secrecy.
pub struct RatchetAeadSender(RatchetAeadSession);

impl RatchetAeadSender {
    pub fn new(master_key: &[u8], nonce: &[u8], aad: &[u8], n_maps: usize) -> Self {
        RatchetAeadSender(RatchetAeadSession::new(master_key, nonce, aad, n_maps))
    }

    /// Seal the next message. Returns index(8,BE) || committing-AEAD blob.
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

/// Open a sequence of messages sealed by a `RatchetAeadSender`, advancing in lockstep.
pub struct RatchetAeadReceiver(RatchetAeadSession);

impl RatchetAeadReceiver {
    pub fn new(master_key: &[u8], nonce: &[u8], aad: &[u8], n_maps: usize) -> Self {
        RatchetAeadReceiver(RatchetAeadSession::new(master_key, nonce, aad, n_maps))
    }

    /// Open the next message. None on tamper / wrong key, or if the index is in the past.
    pub fn open(&mut self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() < 8 {
            return None;
        }
        let i = u64::from_be_bytes(wire[..8].try_into().ok()?);
        if i < self.0.index {
            return None; // key burned — forward secrecy
        }
        while self.0.index < i {
            let _ = self.0.step(); // fast-forward + burn skipped links
        }
        let (j, msg_key) = self.0.step();
        debug_assert_eq!(j, i);
        let aad = ra_bind_aad(&self.0.aad, i);
        aead_open(&msg_key[..], &wire[8..], &aad, self.0.n_maps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_N_MAPS;

    #[test]
    fn ratchet_aead_session_roundtrip_and_forward_secrecy() {
        let master = b"a forward-secret session master key";
        let nonce = b"session-nonce-001";
        let aad = b"channel-7";
        let convo: [&[u8]; 3] = [b"hello", b"the package is in locker 12", b"burn after reading"];
        let inonces: [&[u8]; 3] = [b"inner-nonce-aaa0", b"inner-nonce-aaa1", b"inner-nonce-aaa2"];

        let mut tx = RatchetAeadSender::new(master, nonce, aad, DEFAULT_N_MAPS);
        let wires: Vec<Vec<u8>> = convo
            .iter()
            .zip(inonces.iter())
            .map(|(m, n)| tx.seal(n, m))
            .collect();

        let mut rx = RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS);
        for (w, m) in wires.iter().zip(convo.iter()) {
            assert_eq!(rx.open(w).as_deref(), Some(*m));
        }

        // forward secrecy: a receiver past message 0/1 cannot reopen them
        let mut late = RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS);
        assert!(late.open(&wires[0]).is_some());
        assert!(late.open(&wires[1]).is_some());
        assert!(late.open(&wires[0]).is_none(), "past message reopened — forward secrecy broken");
        assert!(late.open(&wires[1]).is_none());

        // gap tolerated: a fresh receiver jumps to message 2, but can't go back
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

        assert_eq!(
            RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS)
                .open(&wire)
                .as_deref(),
            Some(&pt[..])
        );
        // tamper an inner ciphertext byte
        let mut bad = wire.clone();
        bad[8 + crate::aead::NONCE_LEN + crate::aead::COMMIT_LEN + 1] ^= 0x01;
        assert!(RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS)
            .open(&bad)
            .is_none());
        // wrong master key
        assert!(RatchetAeadReceiver::new(b"wrong", nonce, aad, DEFAULT_N_MAPS)
            .open(&wire)
            .is_none());
        // bump the wire index -> inner aad mismatch -> open fails
        let mut idx = wire.clone();
        idx[7] ^= 0x01;
        assert!(RatchetAeadReceiver::new(master, nonce, aad, DEFAULT_N_MAPS)
            .open(&idx)
            .is_none());
    }
}
