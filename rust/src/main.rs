//! CLI for the Three-Body Problem Cipher — structured with clap.
//!
//! Every subcommand prints exactly one line to stdout (hex bytes, or "INVALID", or
//! a throughput line for bench/timing). The output format is the parsed contract:
//! `tests/test_rust_parity.py` depends on it byte-for-byte.

use std::time::Instant;

use clap::{Parser, Subcommand};

use chaos_core::{
    aead_open, aead_seal, auth_combine, auth_fingerprint, auth_initiator_finish,
    auth_responder_confirm, auth_responder_respond, auth_transcript, dh_public, dh_raw_shared,
    dh_shared_key, hybrid_combine, hybrid_initiator_key, hybrid_respond, mldsa_public_from_seed,
    mldsa_sign, mldsa_verify, mlkem_decapsulate, mlkem_ek_from_seed, mlkem_encapsulate,
    siv_open, siv_seal, SeekableCtr, stream_open, stream_seal,
    twolock_open, twolock_seal, ChaosEngine, MultiMapEngine, RatchetAeadReceiver,
    RatchetAeadSender, RatchetEngine, DEFAULT_N_MAPS, TWOLOCK_AES, TWOLOCK_CHACHA,
};

// ---- helpers (unchanged from before clap) ----

fn parse_hex_bytes(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0, "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex byte"))
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn parse_inner_alg(s: &str) -> u8 {
    match s.trim() {
        "aes" | "aes-256-gcm" | "1" | "0x01" => TWOLOCK_AES,
        "chacha" | "chacha20-poly1305" | "2" | "0x02" => TWOLOCK_CHACHA,
        other => panic!("unknown inner cipher {other:?} (use aes-256-gcm or chacha20-poly1305)"),
    }
}

fn parse_u128(s: &str) -> u128 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).expect("bad hex integer")
    } else {
        s.parse::<u128>().expect("bad decimal integer")
    }
}

// ---- CLI definition ----

#[derive(Parser)]
#[command(name = "chaos_core", disable_colored_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[command(rename_all = "snake_case")]
enum Command {
    /// Single raw engine — seed/control/nonce as integers
    Ks {
        seed: String,
        control: String,
        nonce: String,
        n: usize,
    },
    /// Single-engine keystream via the seed KDF
    FromMaster {
        key_hex: String,
        nonce_hex: String,
        n: usize,
    },
    /// N-map XOR-combined shipped keystream
    #[command(name = "multimap")]
    MultiMap {
        key_hex: String,
        nonce_hex: String,
        n_maps: usize,
        n: usize,
    },
    /// Forward-secret ratchet keystream
    Ratchet {
        key_hex: String,
        nonce_hex: String,
        epoch_bytes: usize,
        n: usize,
    },
    /// Committing AEAD seal
    AeadSeal {
        key_hex: String,
        nonce_hex: String,
        aad_hex: String,
        pt_hex: String,
        n_maps: usize,
    },
    /// Committing AEAD open
    AeadOpen {
        key_hex: String,
        aad_hex: String,
        blob_hex: String,
        n_maps: usize,
    },
    /// Streaming AEAD seal
    StreamSeal {
        key_hex: String,
        salt_hex: String,
        aad_hex: String,
        n_maps: usize,
        #[arg(num_args = 1..)]
        chunks_hex: Vec<String>,
    },
    /// Streaming AEAD open
    StreamOpen {
        key_hex: String,
        aad_hex: String,
        n_maps: usize,
        blob_hex: String,
    },
    /// Ratchet session AEAD seal
    RatchetAeadSeal {
        master_hex: String,
        nonce_hex: String,
        aad_hex: String,
        n_maps: usize,
        #[arg(num_args = 1..)]
        inner_nonce_pt_pairs: Vec<String>,
    },
    /// Ratchet session AEAD open
    RatchetAeadOpen {
        master_hex: String,
        nonce_hex: String,
        aad_hex: String,
        n_maps: usize,
        #[arg(num_args = 1..)]
        wires_hex: Vec<String>,
    },
    /// Two-locks seal (chaos outer + vetted inner)
    TwolockSeal {
        master_hex: String,
        outer_nonce_hex: String,
        inner_nonce_hex: String,
        aad_hex: String,
        pt_hex: String,
        inner_alg: String,
        n_maps: usize,
    },
    /// Two-locks open
    TwolockOpen {
        master_hex: String,
        aad_hex: String,
        blob_hex: String,
        n_maps: usize,
    },
    /// SIV seal (nonce-misuse-resistant AEAD)
    SivSeal {
        key_hex: String,
        aad_hex: String,
        pt_hex: String,
        n_maps: usize,
    },
    /// SIV open
    SivOpen {
        key_hex: String,
        aad_hex: String,
        blob_hex: String,
        n_maps: usize,
    },
    /// CTR keystream (seekable, random-access)
    CtrKs {
        key_hex: String,
        nonce_hex: String,
        n_maps: usize,
        offset: usize,
        n: usize,
    },
    /// CTR encrypt (seekable, random-access)
    CtrEncrypt {
        key_hex: String,
        nonce_hex: String,
        n_maps: usize,
        offset: usize,
        pt_hex: String,
    },
    /// Classical DH public key
    DhPublic {
        private_hex: String,
    },
    /// Classical DH raw shared secret
    DhRawShared {
        private_hex: String,
        peer_public_hex: String,
    },
    /// Classical DH derived shared key
    DhSharedKey {
        private_hex: String,
        peer_public_hex: String,
        info_hex: String,
    },
    /// ML-KEM encapsulation key from seed
    #[command(name = "mlkem_ek")]
    MlkemEk {
        seed_hex: String,
    },
    /// ML-KEM encapsulate
    #[command(name = "mlkem_encapsulate")]
    MlkemEncap {
        ek_hex: String,
        m_hex: String,
    },
    /// ML-KEM decapsulate
    #[command(name = "mlkem_decapsulate")]
    MlkemDecap {
        seed_hex: String,
        ct_hex: String,
    },
    /// Hybrid key combine
    HybridCombine {
        classical_hex: String,
        pq_hex: String,
        info_hex: String,
        dh_a_hex: String,
        dh_b_hex: String,
        kem_pk_a_hex: String,
        kem_ct_hex: String,
    },
    /// Hybrid responder
    HybridRespond {
        dh_private_b_hex: String,
        dh_peer_a_hex: String,
        kem_pk_a_hex: String,
        m_hex: String,
        info_hex: String,
    },
    /// Hybrid initiator key
    HybridInitiatorKey {
        dh_private_a_hex: String,
        kem_seed_hex: String,
        dh_peer_b_hex: String,
        kem_ct_hex: String,
        info_hex: String,
    },
    /// ML-DSA verifying key from seed
    MldsaPublic {
        seed_hex: String,
    },
    /// ML-DSA sign (deterministic)
    MldsaSign {
        seed_hex: String,
        msg_hex: String,
    },
    /// ML-DSA verify
    MldsaVerify {
        public_hex: String,
        msg_hex: String,
        sig_hex: String,
    },
    /// Auth fingerprint
    AuthFingerprint {
        sig_public_hex: String,
        static_public_hex: String,
    },
    /// Auth transcript
    AuthTranscript {
        init_sig_pub: String,
        init_static_pub: String,
        resp_sig_pub: String,
        resp_static_pub: String,
        dh_i: String,
        kem_pk_i: String,
        dh_r: String,
        kem_ct: String,
    },
    /// Auth combine
    AuthCombine {
        ee_hex: String,
        pq_hex: String,
        es_hex: String,
        se_hex: String,
        transcript_hex: String,
        info_hex: String,
    },
    /// Auth responder respond
    AuthResponderRespond {
        resp_sig_seed: String,
        resp_static_priv: String,
        resp_eph_priv: String,
        init_sig_pub: String,
        init_static_pub: String,
        dh_i: String,
        kem_pk_i: String,
        kem_m: String,
        info: String,
    },
    /// Auth initiator finish
    AuthInitiatorFinish {
        init_sig_seed: String,
        init_static_priv: String,
        init_eph_priv: String,
        init_kem_seed: String,
        resp_sig_pub: String,
        resp_static_pub: String,
        dh_r: String,
        kem_ct: String,
        sig_r: String,
        info: String,
    },
    /// Auth responder confirm
    AuthResponderConfirm {
        transcript_hex: String,
        init_sig_pub_hex: String,
        sig_i_hex: String,
    },
    /// Benchmark the shipped multimap combiner
    #[command(name = "benchmm")]
    BenchMm {
        n_maps: Option<usize>,
        #[arg(default_value = "64")]
        mbytes: usize,
    },
    /// Benchmark single-engine throughput
    Bench {
        #[arg(default_value = "64")]
        mbytes: usize,
    },
    /// Constant-time probe: measure key-dependent timing spread
    Timing {
        #[arg(default_value = "64")]
        keys: usize,
    },
}

// ---- main dispatcher ----

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Ks { seed, control, nonce, n } => {
            let ks = ChaosEngine::new(parse_u128(&seed), parse_u128(&control), parse_u128(&nonce)).keystream(n);
            println!("{}", hex_of(&ks));
        }
        Command::FromMaster { key_hex, nonce_hex, n } => {
            let ks = ChaosEngine::from_master(&parse_hex_bytes(&key_hex), &parse_hex_bytes(&nonce_hex)).keystream(n);
            println!("{}", hex_of(&ks));
        }
        Command::MultiMap { key_hex, nonce_hex, n_maps, n } => {
            let ks = MultiMapEngine::new(&parse_hex_bytes(&key_hex), &parse_hex_bytes(&nonce_hex), n_maps).keystream(n);
            println!("{}", hex_of(&ks));
        }
        Command::Ratchet { key_hex, nonce_hex, epoch_bytes, n } => {
            let ks = RatchetEngine::new(&parse_hex_bytes(&key_hex), &parse_hex_bytes(&nonce_hex), epoch_bytes, DEFAULT_N_MAPS).keystream(n);
            println!("{}", hex_of(&ks));
        }
        Command::AeadSeal { key_hex, nonce_hex, aad_hex, pt_hex, n_maps } => {
            let blob = aead_seal(&parse_hex_bytes(&key_hex), &parse_hex_bytes(&nonce_hex), &parse_hex_bytes(&pt_hex), &parse_hex_bytes(&aad_hex), n_maps);
            println!("{}", hex_of(&blob));
        }
        Command::AeadOpen { key_hex, aad_hex, blob_hex, n_maps } => {
            let key = parse_hex_bytes(&key_hex);
            let blob = parse_hex_bytes(&blob_hex);
            let aad = parse_hex_bytes(&aad_hex);
            match aead_open(&key, &blob, &aad, n_maps) {
                Some(pt) => println!("{}", hex_of(&pt)),
                None => println!("INVALID"),
            }
        }
        Command::StreamSeal { key_hex, salt_hex, aad_hex, n_maps, chunks_hex } => {
            let key = parse_hex_bytes(&key_hex);
            let salt = parse_hex_bytes(&salt_hex);
            let aad = parse_hex_bytes(&aad_hex);
            let chunk_vecs: Vec<Vec<u8>> = chunks_hex.iter().map(|a| parse_hex_bytes(a)).collect();
            let chunks: Vec<&[u8]> = chunk_vecs.iter().map(|v| v.as_slice()).collect();
            println!("{}", hex_of(&stream_seal(&key, &salt, &chunks, &aad, n_maps)));
        }
        Command::StreamOpen { key_hex, aad_hex, n_maps, blob_hex } => {
            let key = parse_hex_bytes(&key_hex);
            let blob = parse_hex_bytes(&blob_hex);
            let aad = parse_hex_bytes(&aad_hex);
            match stream_open(&key, &blob, &aad, n_maps) {
                Some(pt) => println!("{}", hex_of(&pt)),
                None => println!("INVALID"),
            }
        }
        Command::RatchetAeadSeal { master_hex, nonce_hex, aad_hex, n_maps, inner_nonce_pt_pairs } => {
            let master = parse_hex_bytes(&master_hex);
            let nonce = parse_hex_bytes(&nonce_hex);
            let aad = parse_hex_bytes(&aad_hex);
            let rest = inner_nonce_pt_pairs;
            assert!(rest.len().is_multiple_of(2), "need <inner_nonce> <pt> pairs");
            let mut sender = RatchetAeadSender::new(&master, &nonce, &aad, n_maps);
            let wires: Vec<String> = rest
                .chunks(2)
                .map(|pair| {
                    let inner_nonce = parse_hex_bytes(&pair[0]);
                    let pt = parse_hex_bytes(&pair[1]);
                    hex_of(&sender.seal(&inner_nonce, &pt))
                })
                .collect();
            println!("{}", wires.join(" "));
        }
        Command::RatchetAeadOpen { master_hex, nonce_hex, aad_hex, n_maps, wires_hex } => {
            let master = parse_hex_bytes(&master_hex);
            let nonce = parse_hex_bytes(&nonce_hex);
            let aad = parse_hex_bytes(&aad_hex);
            let mut receiver = RatchetAeadReceiver::new(&master, &nonce, &aad, n_maps);
            let mut outs: Vec<String> = Vec::new();
            let mut ok = true;
            for w in &wires_hex {
                let wire = parse_hex_bytes(w);
                match receiver.open(&wire) {
                    Some(pt) => outs.push(hex_of(&pt)),
                    None => { ok = false; break; }
                }
            }
            if ok { println!("{}", outs.join(" ")); }
            else { println!("INVALID"); }
        }
        Command::TwolockSeal { master_hex, outer_nonce_hex, inner_nonce_hex, aad_hex, pt_hex, inner_alg, n_maps } => {
            let master = parse_hex_bytes(&master_hex);
            let outer_nonce = parse_hex_bytes(&outer_nonce_hex);
            let inner_nonce = parse_hex_bytes(&inner_nonce_hex);
            let aad = parse_hex_bytes(&aad_hex);
            let pt = parse_hex_bytes(&pt_hex);
            let alg = parse_inner_alg(&inner_alg);
            match twolock_seal(&master, &outer_nonce, &inner_nonce, &pt, &aad, alg, n_maps) {
                Some(blob) => println!("{}", hex_of(&blob)),
                None => println!("INVALID"),
            }
        }
        Command::TwolockOpen { master_hex, aad_hex, blob_hex, n_maps } => {
            let master = parse_hex_bytes(&master_hex);
            let blob = parse_hex_bytes(&blob_hex);
            let aad = parse_hex_bytes(&aad_hex);
            match twolock_open(&master, &blob, &aad, n_maps) {
                Some(pt) => println!("{}", hex_of(&pt)),
                None => println!("INVALID"),
            }
        }
        Command::SivSeal { key_hex, aad_hex, pt_hex, n_maps } => {
            let key = parse_hex_bytes(&key_hex);
            let aad = parse_hex_bytes(&aad_hex);
            let pt = parse_hex_bytes(&pt_hex);
            println!("{}", hex_of(&siv_seal(&key, &pt, &aad, n_maps)));
        }
        Command::SivOpen { key_hex, aad_hex, blob_hex, n_maps } => {
            let key = parse_hex_bytes(&key_hex);
            let aad = parse_hex_bytes(&aad_hex);
            let blob = parse_hex_bytes(&blob_hex);
            match siv_open(&key, &blob, &aad, n_maps) {
                Some(pt) => println!("{}", hex_of(&pt)),
                None => println!("INVALID"),
            }
        }
        Command::CtrKs { key_hex, nonce_hex, n_maps, offset, n } => {
            let key = parse_hex_bytes(&key_hex);
            let nonce = parse_hex_bytes(&nonce_hex);
            let ks = SeekableCtr::new(&key, &nonce, n_maps).keystream(n, offset);
            println!("{}", hex_of(&ks));
        }
        Command::CtrEncrypt { key_hex, nonce_hex, n_maps, offset, pt_hex } => {
            let key = parse_hex_bytes(&key_hex);
            let nonce = parse_hex_bytes(&nonce_hex);
            let pt = parse_hex_bytes(&pt_hex);
            let ct = SeekableCtr::new(&key, &nonce, n_maps).encrypt(&pt, offset);
            println!("{}", hex_of(&ct));
        }
        Command::DhPublic { private_hex } => {
            match dh_public(&parse_hex_bytes(&private_hex)) {
                Some(p) => println!("{}", hex_of(&p)),
                None => println!("INVALID"),
            }
        }
        Command::DhRawShared { private_hex, peer_public_hex } => {
            match dh_raw_shared(&parse_hex_bytes(&private_hex), &parse_hex_bytes(&peer_public_hex)) {
                Some(s) => println!("{}", hex_of(&s)),
                None => println!("INVALID"),
            }
        }
        Command::DhSharedKey { private_hex, peer_public_hex, info_hex } => {
            match dh_shared_key(&parse_hex_bytes(&private_hex), &parse_hex_bytes(&peer_public_hex), &parse_hex_bytes(&info_hex)) {
                Some(k) => println!("{}", hex_of(&k)),
                None => println!("INVALID"),
            }
        }
        Command::MlkemEk { seed_hex } => {
            match mlkem_ek_from_seed(&parse_hex_bytes(&seed_hex)) {
                Some(ek) => println!("{}", hex_of(&ek)),
                None => println!("INVALID"),
            }
        }
        Command::MlkemEncap { ek_hex, m_hex } => {
            match mlkem_encapsulate(&parse_hex_bytes(&ek_hex), &parse_hex_bytes(&m_hex)) {
                Some((ct, ss)) => println!("{} {}", hex_of(&ct), hex_of(&ss)),
                None => println!("INVALID"),
            }
        }
        Command::MlkemDecap { seed_hex, ct_hex } => {
            match mlkem_decapsulate(&parse_hex_bytes(&seed_hex), &parse_hex_bytes(&ct_hex)) {
                Some(ss) => println!("{}", hex_of(&ss)),
                None => println!("INVALID"),
            }
        }
        Command::HybridCombine { classical_hex, pq_hex, info_hex, dh_a_hex, dh_b_hex, kem_pk_a_hex, kem_ct_hex } => {
            let key = hybrid_combine(
                &parse_hex_bytes(&classical_hex), &parse_hex_bytes(&pq_hex), &parse_hex_bytes(&info_hex),
                &parse_hex_bytes(&dh_a_hex), &parse_hex_bytes(&dh_b_hex),
                &parse_hex_bytes(&kem_pk_a_hex), &parse_hex_bytes(&kem_ct_hex),
            );
            println!("{}", hex_of(&key));
        }
        Command::HybridRespond { dh_private_b_hex, dh_peer_a_hex, kem_pk_a_hex, m_hex, info_hex } => {
            match hybrid_respond(&parse_hex_bytes(&dh_private_b_hex), &parse_hex_bytes(&dh_peer_a_hex),
                &parse_hex_bytes(&kem_pk_a_hex), &parse_hex_bytes(&m_hex), &parse_hex_bytes(&info_hex)) {
                Some((dh_b, ct, key)) => println!("{} {} {}", hex_of(&dh_b), hex_of(&ct), hex_of(&key)),
                None => println!("INVALID"),
            }
        }
        Command::HybridInitiatorKey { dh_private_a_hex, kem_seed_hex, dh_peer_b_hex, kem_ct_hex, info_hex } => {
            match hybrid_initiator_key(&parse_hex_bytes(&dh_private_a_hex), &parse_hex_bytes(&kem_seed_hex),
                &parse_hex_bytes(&dh_peer_b_hex), &parse_hex_bytes(&kem_ct_hex), &parse_hex_bytes(&info_hex)) {
                Some(k) => println!("{}", hex_of(&k)),
                None => println!("INVALID"),
            }
        }
        Command::MldsaPublic { seed_hex } => {
            match mldsa_public_from_seed(&parse_hex_bytes(&seed_hex)) {
                Some(pk) => println!("{}", hex_of(&pk)),
                None => println!("INVALID"),
            }
        }
        Command::MldsaSign { seed_hex, msg_hex } => {
            match mldsa_sign(&parse_hex_bytes(&seed_hex), &parse_hex_bytes(&msg_hex)) {
                Some(sig) => println!("{}", hex_of(&sig)),
                None => println!("INVALID"),
            }
        }
        Command::MldsaVerify { public_hex, msg_hex, sig_hex } => {
            let result = mldsa_verify(&parse_hex_bytes(&public_hex), &parse_hex_bytes(&msg_hex), &parse_hex_bytes(&sig_hex));
            println!("{}", if result { "OK" } else { "FAIL" });
        }
        Command::AuthFingerprint { sig_public_hex, static_public_hex } => {
            let fp = auth_fingerprint(&parse_hex_bytes(&sig_public_hex), &parse_hex_bytes(&static_public_hex));
            println!("{}", hex_of(&fp));
        }
        Command::AuthTranscript { init_sig_pub, init_static_pub, resp_sig_pub, resp_static_pub, dh_i, kem_pk_i, dh_r, kem_ct } => {
            let tr = auth_transcript(
                &parse_hex_bytes(&init_sig_pub), &parse_hex_bytes(&init_static_pub),
                &parse_hex_bytes(&resp_sig_pub), &parse_hex_bytes(&resp_static_pub),
                &parse_hex_bytes(&dh_i), &parse_hex_bytes(&kem_pk_i),
                &parse_hex_bytes(&dh_r), &parse_hex_bytes(&kem_ct),
            );
            println!("{}", hex_of(&tr));
        }
        Command::AuthCombine { ee_hex, pq_hex, es_hex, se_hex, transcript_hex, info_hex } => {
            let key = auth_combine(
                &parse_hex_bytes(&ee_hex), &parse_hex_bytes(&pq_hex),
                &parse_hex_bytes(&es_hex), &parse_hex_bytes(&se_hex),
                &parse_hex_bytes(&transcript_hex), &parse_hex_bytes(&info_hex),
            );
            println!("{}", hex_of(&key));
        }
        Command::AuthResponderRespond { resp_sig_seed, resp_static_priv, resp_eph_priv,
            init_sig_pub, init_static_pub, dh_i, kem_pk_i, kem_m, info } => {
            match auth_responder_respond(
                &parse_hex_bytes(&resp_sig_seed), &parse_hex_bytes(&resp_static_priv),
                &parse_hex_bytes(&resp_eph_priv), &parse_hex_bytes(&init_sig_pub),
                &parse_hex_bytes(&init_static_pub), &parse_hex_bytes(&dh_i),
                &parse_hex_bytes(&kem_pk_i), &parse_hex_bytes(&kem_m),
                &parse_hex_bytes(&info),
            ) {
                Some((dh_r, kem_ct, sig_r, key, transcript)) => println!("{} {} {} {} {}",
                    hex_of(&dh_r), hex_of(&kem_ct), hex_of(&sig_r), hex_of(&key), hex_of(&transcript)),
                None => println!("INVALID"),
            }
        }
        Command::AuthInitiatorFinish { init_sig_seed, init_static_priv, init_eph_priv,
            init_kem_seed, resp_sig_pub, resp_static_pub, dh_r, kem_ct, sig_r, info } => {
            match auth_initiator_finish(
                &parse_hex_bytes(&init_sig_seed), &parse_hex_bytes(&init_static_priv),
                &parse_hex_bytes(&init_eph_priv), &parse_hex_bytes(&init_kem_seed),
                &parse_hex_bytes(&resp_sig_pub), &parse_hex_bytes(&resp_static_pub),
                &parse_hex_bytes(&dh_r), &parse_hex_bytes(&kem_ct),
                &parse_hex_bytes(&sig_r), &parse_hex_bytes(&info),
            ) {
                Some((key, sig_i)) => println!("{} {}", hex_of(&key), hex_of(&sig_i)),
                None => println!("INVALID"),
            }
        }
        Command::AuthResponderConfirm { transcript_hex, init_sig_pub_hex, sig_i_hex } => {
            let ok = auth_responder_confirm(
                &parse_hex_bytes(&transcript_hex), &parse_hex_bytes(&init_sig_pub_hex), &parse_hex_bytes(&sig_i_hex),
            );
            println!("{}", if ok { "OK" } else { "FAIL" });
        }
        Command::BenchMm { n_maps, mbytes } => {
            let n_maps = n_maps.unwrap_or(DEFAULT_N_MAPS);
            let n = mbytes * 1024 * 1024;
            let mut eng = MultiMapEngine::new(b"bench-master-key", b"bench-nonce", n_maps);
            let _ = eng.keystream(1 << 16);
            let t0 = Instant::now();
            let mut sink: u64 = 0;
            let mut produced = 0usize;
            while produced < n {
                let chunk = eng.keystream(1 << 20);
                for b in &chunk { sink ^= *b as u64; }
                produced += chunk.len();
            }
            let dt = t0.elapsed().as_secs_f64();
            let mbps = (produced as f64 / (1024.0 * 1024.0)) / dt;
            eprintln!("checksum {sink}");
            println!("{n_maps}-map: {mbps:.2} MB/s  ({mbytes} MB in {dt:.3}s)");
        }
        Command::Bench { mbytes } => {
            let n = mbytes * 1024 * 1024;
            let mut eng = ChaosEngine::new(
                0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210_FEDC_BA98_7654_3210,
                0xA5A5_A5A5,
            );
            let _ = eng.keystream(1 << 16);
            let t0 = Instant::now();
            let mut sink: u64 = 0;
            let mut produced = 0usize;
            while produced < n {
                let chunk = eng.keystream(1 << 20);
                for b in &chunk { sink ^= *b as u64; }
                produced += chunk.len();
            }
            let dt = t0.elapsed().as_secs_f64();
            let mbps = (produced as f64 / (1024.0 * 1024.0)) / dt;
            eprintln!("checksum {sink}");
            println!("{mbps:.2} MB/s  ({mbytes} MB in {dt:.3}s)");
        }
        Command::Timing { keys } => {
            let bytes_per_key = 1 << 20;
            let reps = 15;
            let mut times: Vec<f64> = Vec::with_capacity(keys);
            for k in 0..keys {
                let control = (k as u128)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15_1234_5678_9ABC_DEF1)
                    .wrapping_add(0xA5A5_A5A5_5A5A_5A5A);
                let mut best = f64::INFINITY;
                for _ in 0..reps {
                    let mut eng = ChaosEngine::new(0xDEAD_BEEF, control, 0xC0FFEE);
                    let _ = eng.keystream(1 << 14);
                    let t0 = Instant::now();
                    let chunk = eng.keystream(bytes_per_key);
                    let dt = t0.elapsed().as_secs_f64();
                    let mut sink = 0u64;
                    for b in &chunk { sink ^= *b as u64; }
                    std::hint::black_box(sink);
                    let ns_per_byte = dt * 1e9 / bytes_per_key as f64;
                    if ns_per_byte < best { best = ns_per_byte; }
                }
                times.push(best);
            }
            times.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let median = times[times.len() / 2];
            let lo = times[0];
            let p95 = times[(times.len() * 95 / 100).min(times.len() - 1)];
            let hi = times[times.len() - 1];
            let spread = (p95 - lo) / median * 100.0;
            println!("keys={keys}  ns/byte floors: min {lo:.3}  median {median:.3}  p95 {p95:.3}  max {hi:.3}");
            println!("secret-dependent spread (p95-min)/median: {spread:.2}%  (small = no key-dependent timing)");
        }
    }
}
