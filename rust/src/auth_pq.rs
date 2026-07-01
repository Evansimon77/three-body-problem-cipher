//! Authenticated post-quantum key agreement (Phase 8.6).
//!
//! Port of auth_pq_keyexchange.py. Phase 8.5 stops a passive recorder; it does NOT
//! stop an active man-in-the-middle. This module closes that: it adds MUTUAL
//! authentication, hybrid on BOTH axes:
//!   * STATIC triple-DH binding — the decades-studied discrete-log identity proof, AND
//!   * ML-DSA-65 signatures (FIPS 204) over the full transcript — a post-quantum identity proof.
//!
//! An attacker must defeat BOTH to impersonate. NONE of the primitives are hand-rolled:
//! ML-DSA is RustCrypto's reviewed `ml-dsa` crate, proven to interoperate with Python's
//! OpenSSL 3.5 byte-for-byte.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey, B32,
};

use sha2::{Digest, Sha256, Sha512};

use crate::keyexchange::{dh_public, dh_raw_shared, mlkem_decapsulate, mlkem_ek_from_seed, mlkem_encapsulate, DH_BYTES};

const AUTH_KDF_LABEL: &[u8] = b"chaos-pwlcm-v1|auth-pq|dh2048+mlkem768+mldsa65|v1";
const AUTH_SIG_CTX_INITIATOR: &[u8] = b"chaos-pwlcm-v1|auth-pq|sig|initiator|v1";
const AUTH_SIG_CTX_RESPONDER: &[u8] = b"chaos-pwlcm-v1|auth-pq|sig|responder|v1";
const MLDSA_CONTEXT: &[u8] = b"";

/// ML-DSA-65 fixed sizes (FIPS 204).
pub const MLDSA_SEED_LEN: usize = 32;
pub const MLDSA_PUB_LEN: usize = 1952;
pub const MLDSA_SIG_LEN: usize = 3309;

fn mldsa_signing_key(seed: &[u8]) -> Option<SigningKey<MlDsa65>> {
    let s = B32::try_from(seed).ok()?;
    Some(SigningKey::<MlDsa65>::from_seed(&s))
}

/// The 1952-byte verifying (public) key for a given seed.
pub fn mldsa_public_from_seed(seed: &[u8]) -> Option<[u8; MLDSA_PUB_LEN]> {
    let sk = mldsa_signing_key(seed)?;
    let enc = sk.verifying_key().encode();
    let mut out = [0u8; MLDSA_PUB_LEN];
    out.copy_from_slice(&enc[..]);
    Some(out)
}

/// Deterministically sign a message under the seed's ML-DSA-65 key.
pub fn mldsa_sign(seed: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let sk = mldsa_signing_key(seed)?;
    let sig = sk.expanded_key().sign_deterministic(msg, MLDSA_CONTEXT).ok()?;
    Some(sig.encode().to_vec())
}

/// Verify an ML-DSA-65 signature. Fails closed (false) on any malformed input.
pub fn mldsa_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let enc_vk = match EncodedVerifyingKey::<MlDsa65>::try_from(public) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
    let enc_sig = match EncodedSignature::<MlDsa65>::try_from(sig) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let sig = match Signature::<MlDsa65>::decode(&enc_sig) {
        Some(s) => s,
        None => return false,
    };
    vk.verify_with_context(msg, MLDSA_CONTEXT, &sig)
}

/// Left-pad a big-endian DH value to the fixed 256-byte transcript width.
fn enc_dh(bytes: &[u8]) -> [u8; DH_BYTES] {
    let mut out = [0u8; DH_BYTES];
    out[DH_BYTES - bytes.len()..].copy_from_slice(bytes);
    out
}

/// Short human-verifiable fingerprint binding BOTH of a peer's identity keys.
pub fn auth_fingerprint(sig_public: &[u8], static_public: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(sig_public);
    h.update(enc_dh(static_public));
    let digest = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// The handshake transcript: SHA-512 over BOTH identities + every public value.
#[allow(clippy::too_many_arguments)]
pub fn auth_transcript(
    init_sig_public: &[u8],
    init_static_public: &[u8],
    resp_sig_public: &[u8],
    resp_static_public: &[u8],
    dh_i: &[u8],
    kem_pk_i: &[u8],
    dh_r: &[u8],
    kem_ct: &[u8],
) -> [u8; 64] {
    let init_static = enc_dh(init_static_public);
    let resp_static = enc_dh(resp_static_public);
    let dh_i_p = enc_dh(dh_i);
    let dh_r_p = enc_dh(dh_r);
    let mut h = Sha512::new();
    for part in [
        init_sig_public,
        init_static.as_slice(),
        resp_sig_public,
        resp_static.as_slice(),
        dh_i_p.as_slice(),
        kem_pk_i,
        dh_r_p.as_slice(),
        kem_ct,
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    let digest = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// The authenticated combiner: mix the two confidentiality secrets AND the static identity terms.
pub fn auth_combine(
    ee: &[u8],
    pq: &[u8],
    es: &[u8],
    se: &[u8],
    transcript: &[u8],
    info: &[u8],
) -> [u8; 32] {
    let (lo, hi) = if es <= se { (es, se) } else { (se, es) };
    let mut h = Sha512::new();
    h.update(AUTH_KDF_LABEL);
    for part in [ee, pq, lo, hi, transcript, info] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Responder's flight 2: encapsulate, derive the session key, sign the transcript.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn auth_responder_respond(
    resp_sig_seed: &[u8],
    resp_static_private: &[u8],
    resp_eph_private: &[u8],
    init_sig_public: &[u8],
    init_static_public: &[u8],
    dh_i: &[u8],
    kem_pk_i: &[u8],
    kem_m: &[u8],
    info: &[u8],
) -> Option<([u8; DH_BYTES], Vec<u8>, Vec<u8>, [u8; 32], [u8; 64])> {
    let resp_sig_public = mldsa_public_from_seed(resp_sig_seed)?;
    let resp_static_public = dh_public(resp_static_private)?;
    let dh_r = dh_public(resp_eph_private)?;
    let (kem_ct, pq) = mlkem_encapsulate(kem_pk_i, kem_m)?;
    let transcript = auth_transcript(
        init_sig_public,
        init_static_public,
        &resp_sig_public,
        &resp_static_public,
        dh_i,
        kem_pk_i,
        &dh_r,
        &kem_ct,
    );
    let ee = dh_raw_shared(resp_eph_private, dh_i)?;
    let es = dh_raw_shared(resp_static_private, dh_i)?;
    let se = dh_raw_shared(resp_eph_private, init_static_public)?;
    let key = auth_combine(&ee, &pq, &es, &se, &transcript, info);
    let msg = [AUTH_SIG_CTX_RESPONDER, &transcript[..]].concat();
    let sig_r = mldsa_sign(resp_sig_seed, &msg)?;
    Some((dh_r, kem_ct, sig_r, key, transcript))
}

/// Initiator's flight 3: verify the responder's signature, derive the key, sign back.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn auth_initiator_finish(
    init_sig_seed: &[u8],
    init_static_private: &[u8],
    init_eph_private: &[u8],
    init_kem_seed: &[u8],
    resp_sig_public: &[u8],
    resp_static_public: &[u8],
    dh_r: &[u8],
    kem_ct: &[u8],
    sig_r: &[u8],
    info: &[u8],
) -> Option<([u8; 32], Vec<u8>)> {
    let init_sig_public = mldsa_public_from_seed(init_sig_seed)?;
    let init_static_public = dh_public(init_static_private)?;
    let dh_i = dh_public(init_eph_private)?;
    let kem_pk_i = mlkem_ek_from_seed(init_kem_seed)?;
    let transcript = auth_transcript(
        &init_sig_public,
        &init_static_public,
        resp_sig_public,
        resp_static_public,
        &dh_i,
        &kem_pk_i,
        dh_r,
        kem_ct,
    );
    let resp_msg = [AUTH_SIG_CTX_RESPONDER, &transcript[..]].concat();
    if !mldsa_verify(resp_sig_public, &resp_msg, sig_r) {
        return None;
    }
    let ee = dh_raw_shared(init_eph_private, dh_r)?;
    let pq = mlkem_decapsulate(init_kem_seed, kem_ct)?;
    let es = dh_raw_shared(init_eph_private, resp_static_public)?;
    let se = dh_raw_shared(init_static_private, dh_r)?;
    let key = auth_combine(&ee, &pq, &es, &se, &transcript, info);
    let init_msg = [AUTH_SIG_CTX_INITIATOR, &transcript[..]].concat();
    let sig_i = mldsa_sign(init_sig_seed, &init_msg)?;
    Some((key, sig_i))
}

/// Responder's confirm: verify the initiator's signature over the transcript.
pub fn auth_responder_confirm(transcript: &[u8], init_sig_public: &[u8], sig_i: &[u8]) -> bool {
    let msg = [AUTH_SIG_CTX_INITIATOR, transcript].concat();
    mldsa_verify(init_sig_public, &msg, sig_i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_sign_verify_and_seed_determinism() {
        let seed: Vec<u8> = (0u8..32).collect();
        let pk = mldsa_public_from_seed(&seed).unwrap();
        assert_eq!(pk.len(), MLDSA_PUB_LEN);
        assert_eq!(mldsa_public_from_seed(&seed).unwrap(), pk);
        let msg = b"authenticate me";
        let sig = mldsa_sign(&seed, msg).unwrap();
        assert_eq!(sig.len(), MLDSA_SIG_LEN);
        assert_eq!(mldsa_sign(&seed, msg).unwrap(), sig);
        assert!(mldsa_verify(&pk, msg, &sig));
        assert!(!mldsa_verify(&pk, b"authenticate Me", &sig));
        let mut bad = sig.clone();
        bad[100] ^= 0x01;
        assert!(!mldsa_verify(&pk, msg, &bad));
        let other_pk = mldsa_public_from_seed(&(1u8..33).collect::<Vec<u8>>()).unwrap();
        assert!(!mldsa_verify(&other_pk, msg, &sig));
        assert!(mldsa_public_from_seed(&seed[..31]).is_none());
        assert!(mldsa_sign(&seed[..31], msg).is_none());
        assert!(!mldsa_verify(&pk[..1951], msg, &sig));
        assert!(!mldsa_verify(&pk, msg, &sig[..3308]));
    }

    #[test]
    fn auth_handshake_agrees_and_catches_impersonation() {
        let a_sig_seed: Vec<u8> = (1u8..33).collect();
        let b_sig_seed: Vec<u8> = (33u8..65).collect();
        let a_static = [0x11u8; 32];
        let a_eph = [0x12u8; 32];
        let b_static = [0x21u8; 32];
        let b_eph = [0x22u8; 32];
        let a_kem_seed: Vec<u8> = (64u8..128).collect();
        let kem_m = [0x7eu8; 32];
        let info = b"auth-pq-channel";

        let a_sig_pub = mldsa_public_from_seed(&a_sig_seed).unwrap();
        let a_static_pub = dh_public(&a_static).unwrap();
        let b_sig_pub = mldsa_public_from_seed(&b_sig_seed).unwrap();
        let b_static_pub = dh_public(&b_static).unwrap();
        let dh_i = dh_public(&a_eph).unwrap();
        let kem_pk_i = mlkem_ek_from_seed(&a_kem_seed).unwrap();

        let (dh_r, kem_ct, sig_r, key_b, transcript) = auth_responder_respond(
            &b_sig_seed, &b_static, &b_eph, &a_sig_pub, &a_static_pub, &dh_i, &kem_pk_i, &kem_m,
            info,
        )
        .unwrap();

        let (key_a, sig_i) = auth_initiator_finish(
            &a_sig_seed, &a_static, &a_eph, &a_kem_seed, &b_sig_pub, &b_static_pub, &dh_r, &kem_ct,
            &sig_r, info,
        )
        .unwrap();
        assert_eq!(key_a, key_b);

        assert!(auth_responder_confirm(&transcript, &a_sig_pub, &sig_i));

        // Impersonation: tampered responder signature -> initiator refuses
        let mut bad_sig_r = sig_r.clone();
        bad_sig_r[200] ^= 0x01;
        assert!(auth_initiator_finish(
            &a_sig_seed, &a_static, &a_eph, &a_kem_seed, &b_sig_pub, &b_static_pub, &dh_r, &kem_ct,
            &bad_sig_r, info,
        )
        .is_none());

        // Impersonation: tampered initiator signature -> responder confirm fails
        let mut bad_sig_i = sig_i.clone();
        bad_sig_i[200] ^= 0x01;
        assert!(!auth_responder_confirm(&transcript, &a_sig_pub, &bad_sig_i));

        // MITM: tampered ciphertext changes the transcript -> sig won't verify
        let mut bad_ct = kem_ct.clone();
        bad_ct[7] ^= 0x01;
        assert!(auth_initiator_finish(
            &a_sig_seed, &a_static, &a_eph, &a_kem_seed, &b_sig_pub, &b_static_pub, &dh_r, &bad_ct,
            &sig_r, info,
        )
        .is_none());

        // Fingerprint binds both identity keys
        let fp = auth_fingerprint(&a_sig_pub, &a_static_pub);
        assert_eq!(fp, auth_fingerprint(&a_sig_pub, &a_static_pub));
        assert_ne!(fp, auth_fingerprint(&b_sig_pub, &b_static_pub));
    }
}
