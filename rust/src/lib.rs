//! Three-Body Problem Cipher — Rust core.
//!
//! A research chaos-based stream cipher: integer PWLCM keystream + AEAD shells
//! on top of vetted HMAC-SHA256, deployed as the OUTER wall over a vetted inner
//! vault (AES-256-GCM / ChaCha20-Poly1305). The chaos layer is UNVETTED and never
//! trusted alone — the inner vault is what guarantees the data.
//!
//! ## Modules
//!
//! | Module | What it is | Python mirror |
//! |--------|-----------|---------------|
//! | `engine` | The chaos map core + shared helpers | `engine.py` |
//! | `multimap` | N independent maps XOR-combined | `multimap.py` |
//! | `ratchet` | Forward-secret re-keying chain | `ratchet.py` |
//! | `aead` | Committing AEAD shell (seal/open) | `aead.py` + `commit.py` |
//! | `streaming` | Chunked/streaming AEAD | `streaming.py` |
//! | `ratchet_aead` | Forward-secret session AEAD | `ratchet_aead.py` |
//! | `twolock` | Chaos outer wall over vetted inner vault | `twolock.py` |
//! | `keyexchange` | DH + ML-KEM-768 hybrid key agreement | `keyexchange.py` + `pq_keyexchange.py` |
//! | `auth_pq` | Authenticated PQ handshake | `auth_pq_keyexchange.py` |
//! | `siv` | Nonce-misuse-resistant AEAD | `siv.py` |
//! | `ctr` | Seekable counter mode | `ctr.py` |
//!
//! ## Running
//!
//! ```bash
//! cargo test --release          # 28 tests
//! cargo build --release         # the CLI binary
//! ```

pub mod aead;
pub mod auth_pq;
pub mod constants;
pub mod ctr;
pub mod engine;
pub mod keyexchange;
pub mod multimap;
pub mod ratchet;
pub mod ratchet_aead;
pub mod siv;
pub mod streaming;
pub mod twolock;
pub(crate) mod utils;

// Re-export the full public API — identical to what the single-file lib.rs exported.
pub use aead::{aead_open, aead_seal, key_commitment, COMMIT_LEN, NONCE_LEN, TAG_LEN};
pub use auth_pq::{
    auth_combine, auth_fingerprint, auth_initiator_finish, auth_responder_confirm,
    auth_responder_respond, auth_transcript, mldsa_public_from_seed, mldsa_sign, mldsa_verify,
    MLDSA_PUB_LEN, MLDSA_SEED_LEN, MLDSA_SIG_LEN,
};
pub use constants::DEFAULT_N_MAPS;
pub use ctr::{SeekableCtr, BLOCK_SIZE};
pub use engine::{
    ChaosEngine,
};
pub use keyexchange::{
    dh_public, dh_raw_shared, dh_shared_key, hybrid_combine, hybrid_initiator_key, hybrid_respond,
    mlkem_decapsulate, mlkem_ek_from_seed, mlkem_encapsulate, DH_BYTES, MLKEM_EK_LEN,
    MLKEM_M_LEN, MLKEM_SEED_LEN,
};
pub use multimap::MultiMapEngine;
pub use ratchet::RatchetEngine;
pub use siv::{siv_open, siv_seal, SIV_LEN};
pub use ratchet_aead::{RatchetAeadReceiver, RatchetAeadSender};
pub use streaming::{stream_open, stream_seal, HEADER_LEN, SALT_LEN};
pub use twolock::{
    twolock_open, twolock_seal, INNER_NONCE_LEN, TWOLOCK_AES, TWOLOCK_CHACHA,
};
