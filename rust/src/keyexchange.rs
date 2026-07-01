//! Key agreement — classical DH + post-quantum hybrid (Phase 8.5).
//!
//! Port of keyexchange.py + pq_keyexchange.py. How two parties who share NO secret
//! agree on one over an open wire. Unlike the chaos keystream, NONE of this is hand-rolled:
//!   * CLASSICAL half: RFC 3526 MODP Group 14 (2048-bit DH), reusing `ruint`;
//!   * POST-QUANTUM half: ML-KEM-768 (FIPS 203) from RustCrypto's `ml-kem` crate.
//!
//! The hybrid COMBINER mixes BOTH shared secrets, so the session key survives a
//! quantum break of DH *or* a classical break of ML-KEM.
//!
//! UNAUTHENTICATED — stops a passive recorder, not an active man-in-the-middle.
//! That is the separate authenticated handshake (auth_pq).

use ml_kem::kem::{Decapsulate, FromSeed, KeyExport, TryKeyInit};
use ml_kem::{MlKem768, Seed};
use sha2::{Digest, Sha512};



/// RFC 3526 MODP Group 14, the 2048-bit safe prime.
const DH_P_HEX: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff";
const DH_G: u64 = 2;
/// Fixed-width DH element encoding: 2048 bits = 256 bytes.
pub const DH_BYTES: usize = 256;
const DH_KDF_LABEL: &[u8] = b"chaos-pwlcm-v1|dh-shared-key";
const PQ_KDF_LABEL: &[u8] = b"chaos-pwlcm-v1|pq-hybrid|dh-2048+ml-kem-768|v1";

/// ML-KEM-768 fixed sizes (FIPS 203).
pub const MLKEM_SEED_LEN: usize = 64;
pub const MLKEM_EK_LEN: usize = 1184;
pub const MLKEM_M_LEN: usize = 32;

type DhUint = ruint::Uint<2048, 32>;

fn dh_prime() -> DhUint {
    DhUint::from_str_radix(DH_P_HEX, 16).expect("the RFC 3526 prime is valid hex")
}

fn dh_parse(bytes: &[u8]) -> Option<DhUint> {
    if bytes.len() > DH_BYTES {
        return None;
    }
    Some(DhUint::from_be_slice(bytes))
}

fn dh_in_range(x: DhUint, p: DhUint) -> bool {
    let two = DhUint::from(2u64);
    x >= two && x <= p - two
}

/// g^private mod p — the public value safe to send on the wire.
pub fn dh_public(private: &[u8]) -> Option<[u8; DH_BYTES]> {
    let p = dh_prime();
    let x = dh_parse(private)?;
    if !dh_in_range(x, p) {
        return None;
    }
    Some(DhUint::from(DH_G).pow_mod(x, p).to_be_bytes::<DH_BYTES>())
}

/// The validated raw DH group element g^(ab) mod p as 256 fixed-width bytes.
pub fn dh_raw_shared(private: &[u8], peer_public: &[u8]) -> Option<[u8; DH_BYTES]> {
    let p = dh_prime();
    let x = dh_parse(private)?;
    let peer = dh_parse(peer_public)?;
    if !dh_in_range(x, p) || !dh_in_range(peer, p) {
        return None;
    }
    Some(peer.pow_mod(x, p).to_be_bytes::<DH_BYTES>())
}

/// SHA-512 KDF of the raw shared element down to a 32-byte master key.
pub fn dh_shared_key(private: &[u8], peer_public: &[u8], info: &[u8]) -> Option<[u8; 32]> {
    let raw = dh_raw_shared(private, peer_public)?;
    let mut h = Sha512::new();
    h.update(DH_KDF_LABEL);
    h.update(b"|");
    h.update(info);
    h.update(b"|");
    h.update(raw);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    Some(out)
}

type Mlkem768Dk = ml_kem::ml_kem_768::DecapsulationKey;
type Mlkem768Ek = ml_kem::ml_kem_768::EncapsulationKey;

fn mlkem_keypair(seed: &[u8]) -> Option<(Mlkem768Dk, Mlkem768Ek)> {
    if seed.len() != MLKEM_SEED_LEN {
        return None;
    }
    let s = Seed::try_from(seed).ok()?;
    Some(MlKem768::from_seed(&s))
}

/// The 1184-byte encapsulation (public) key for a given seed.
pub fn mlkem_ek_from_seed(seed: &[u8]) -> Option<[u8; MLKEM_EK_LEN]> {
    let (_dk, ek) = mlkem_keypair(seed)?;
    let bytes = ek.to_bytes();
    let mut out = [0u8; MLKEM_EK_LEN];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Deterministic ML-KEM-768 encapsulation. Returns (ciphertext, shared_secret).
pub fn mlkem_encapsulate(ek_bytes: &[u8], m: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
    if m.len() != MLKEM_M_LEN {
        return None;
    }
    let ek = Mlkem768Ek::new_from_slice(ek_bytes).ok()?;
    let mm = ml_kem::B32::try_from(m).ok()?;
    let (ct, ss) = ek.encapsulate_deterministic(&mm);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&ss);
    Some((ct.as_slice().to_vec(), secret))
}

/// ML-KEM-768 decapsulation.
pub fn mlkem_decapsulate(seed: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
    let (dk, _ek) = mlkem_keypair(seed)?;
    let ss = dk.decapsulate_slice(ct).ok()?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&ss);
    Some(secret)
}

/// Left-pad a big-endian DH value to the fixed 256-byte transcript width.
fn enc_dh(bytes: &[u8]) -> [u8; DH_BYTES] {
    let mut out = [0u8; DH_BYTES];
    out[DH_BYTES - bytes.len()..].copy_from_slice(bytes);
    out
}

/// The hybrid combiner (NIST SP 800-56C style): hash BOTH shared secrets with the full transcript.
pub fn hybrid_combine(
    classical: &[u8],
    pq: &[u8],
    info: &[u8],
    dh_a: &[u8],
    dh_b: &[u8],
    kem_pk_a: &[u8],
    kem_ct: &[u8],
) -> [u8; 32] {
    let mut transcript = Vec::with_capacity(2 * DH_BYTES + kem_pk_a.len() + kem_ct.len());
    transcript.extend_from_slice(&enc_dh(dh_a));
    transcript.extend_from_slice(&enc_dh(dh_b));
    transcript.extend_from_slice(kem_pk_a);
    transcript.extend_from_slice(kem_ct);

    let mut h = Sha512::new();
    h.update(PQ_KDF_LABEL);
    for part in [classical, pq, info, &transcript[..]] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Responder side of the hybrid handshake.
#[allow(clippy::type_complexity)]
pub fn hybrid_respond(
    dh_private_b: &[u8],
    dh_peer_a: &[u8],
    kem_pk_a: &[u8],
    m: &[u8],
    info: &[u8],
) -> Option<([u8; DH_BYTES], Vec<u8>, [u8; 32])> {
    let classical = dh_raw_shared(dh_private_b, dh_peer_a)?;
    let dh_b = dh_public(dh_private_b)?;
    let (ct, pq) = mlkem_encapsulate(kem_pk_a, m)?;
    let key = hybrid_combine(&classical, &pq, info, dh_peer_a, &dh_b, kem_pk_a, &ct);
    Some((dh_b, ct, key))
}

/// Initiator side of the hybrid handshake.
pub fn hybrid_initiator_key(
    dh_private_a: &[u8],
    kem_seed: &[u8],
    dh_peer_b: &[u8],
    kem_ct: &[u8],
    info: &[u8],
) -> Option<[u8; 32]> {
    let classical = dh_raw_shared(dh_private_a, dh_peer_b)?;
    let pq = mlkem_decapsulate(kem_seed, kem_ct)?;
    let dh_a = dh_public(dh_private_a)?;
    let kem_pk_a = mlkem_ek_from_seed(kem_seed)?;
    Some(hybrid_combine(
        &classical, &pq, info, &dh_a, dh_peer_b, &kem_pk_a, kem_ct,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_agreement_and_kdf_roundtrip() {
        let a = [0x42u8; 32];
        let b = [0x99u8; 32];
        let pub_a = dh_public(&a).unwrap();
        let pub_b = dh_public(&b).unwrap();
        assert_eq!(dh_raw_shared(&a, &pub_b).unwrap(), dh_raw_shared(&b, &pub_a).unwrap());
        let info = b"channel-7";
        assert_eq!(
            dh_shared_key(&a, &pub_b, info).unwrap(),
            dh_shared_key(&b, &pub_a, info).unwrap()
        );
        assert_ne!(
            dh_shared_key(&a, &pub_b, info).unwrap(),
            dh_shared_key(&a, &pub_b, b"other").unwrap()
        );
    }

    #[test]
    fn dh_rejects_degenerate_and_out_of_range() {
        let a = [0x42u8; 32];
        let p = dh_prime();
        let one = 1u64.to_be_bytes();
        let p_minus_1 = (p - DhUint::from(1u64)).to_be_bytes::<DH_BYTES>();
        let p_bytes = p.to_be_bytes::<DH_BYTES>();
        assert!(dh_raw_shared(&a, &[0u8]).is_none());
        assert!(dh_raw_shared(&a, &one).is_none());
        assert!(dh_raw_shared(&a, &p_minus_1).is_none());
        assert!(dh_raw_shared(&a, &p_bytes).is_none());
        assert!(dh_public(&[1u8]).is_none());
        assert!(dh_public(&[0xffu8; DH_BYTES + 1]).is_none());
    }

    #[test]
    fn mlkem_encaps_decaps_roundtrip() {
        let seed: Vec<u8> = (0u8..64).collect();
        let m = [0x5au8; 32];
        let ek = mlkem_ek_from_seed(&seed).unwrap();
        let (ct, ss_send) = mlkem_encapsulate(&ek, &m).unwrap();
        let ss_recv = mlkem_decapsulate(&seed, &ct).unwrap();
        assert_eq!(ss_send, ss_recv);
        let (ct2, _) = mlkem_encapsulate(&ek, &m).unwrap();
        assert_eq!(ct, ct2);
        let other_seed: Vec<u8> = (1u8..65).collect();
        assert_ne!(mlkem_decapsulate(&other_seed, &ct).unwrap(), ss_send);
        assert!(mlkem_encapsulate(&ek, &[0u8; 31]).is_none());
        assert!(mlkem_decapsulate(&seed[..63], &ct).is_none());
    }

    #[test]
    fn hybrid_handshake_agrees() {
        let dh_a = [0x11u8; 32];
        let dh_b = [0x22u8; 32];
        let kem_seed: Vec<u8> = (10u8..74).collect();
        let m = [0x7eu8; 32];
        let info = b"hybrid-channel";

        let dh_a_pub = dh_public(&dh_a).unwrap();
        let kem_pk_a = mlkem_ek_from_seed(&kem_seed).unwrap();
        let (dh_b_pub, ct, key_b) = hybrid_respond(&dh_b, &dh_a_pub, &kem_pk_a, &m, info).unwrap();
        let key_a = hybrid_initiator_key(&dh_a, &kem_seed, &dh_b_pub, &ct, info).unwrap();
        assert_eq!(key_a, key_b, "hybrid initiator and responder must agree");

        let mut bad_ct = ct.clone();
        bad_ct[5] ^= 0x01;
        let key_a_bad = hybrid_initiator_key(&dh_a, &kem_seed, &dh_b_pub, &bad_ct, info);
        assert!(key_a_bad.map(|k| k != key_b).unwrap_or(true));
    }
}
