//! CLI for the chaos core.
//!
//!   chaos_core ks   <seed> <control> <nonce> <n>   -> prints n keystream bytes as hex
//!   chaos_core bench <mbytes>                       -> generates that many MB, prints MB/s
//!
//! <seed>/<control>/<nonce> accept decimal or 0x-hex (up to 127 bits). The `ks` mode is what
//! tests/test_rust_parity.py calls to compare against kat/vectors.json.

use std::time::Instant;

use chaos_core::{
    aead_open, aead_seal, dh_public, dh_raw_shared, dh_shared_key, hybrid_combine,
    hybrid_initiator_key, hybrid_respond, mlkem_decapsulate, mlkem_ek_from_seed, mlkem_encapsulate,
    stream_open, stream_seal, twolock_open, twolock_seal, ChaosEngine, MultiMapEngine,
    RatchetAeadReceiver, RatchetAeadSender, RatchetEngine, DEFAULT_N_MAPS, TWOLOCK_AES, TWOLOCK_CHACHA,
};

/// Parse a hex byte string (e.g. the KAT key/nonce material) into raw bytes.
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

/// Map an inner-cipher name (or numeric id) to the two-locks alg byte. Accepts the Python shell's
/// names so the same KAT keys ("aes-256-gcm" / "chacha20-poly1305") drive both implementations.
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match mode {
        "ks" => {
            let seed = parse_u128(&args[2]);
            let control = parse_u128(&args[3]);
            let nonce = parse_u128(&args[4]);
            let n: usize = args[5].parse().expect("bad length");
            let ks = ChaosEngine::new(seed, control, nonce).keystream(n);
            println!("{}", hex_of(&ks));
        }
        "from_master" => {
            // chaos_core from_master <key_hex> <nonce_hex> <n>  -> single-engine keystream via the seed KDF
            let key = parse_hex_bytes(&args[2]);
            let nonce = parse_hex_bytes(&args[3]);
            let n: usize = args[4].parse().expect("bad length");
            let ks = ChaosEngine::from_master(&key, &nonce).keystream(n);
            println!("{}", hex_of(&ks));
        }
        "multimap" => {
            // chaos_core multimap <key_hex> <nonce_hex> <n_maps> <n>  -> XOR-combined shipped keystream
            let key = parse_hex_bytes(&args[2]);
            let nonce = parse_hex_bytes(&args[3]);
            let n_maps: usize = args[4].parse().expect("bad n_maps");
            let n: usize = args[5].parse().expect("bad length");
            let ks = MultiMapEngine::new(&key, &nonce, n_maps).keystream(n);
            println!("{}", hex_of(&ks));
        }
        "ratchet" => {
            // chaos_core ratchet <key_hex> <nonce_hex> <epoch_bytes> <n>  -> forward-secret keystream
            // n_maps is the locked default (4); epoch_bytes sets the re-key boundary (must match peer).
            let key = parse_hex_bytes(&args[2]);
            let nonce = parse_hex_bytes(&args[3]);
            let epoch_bytes: usize = args[4].parse().expect("bad epoch_bytes");
            let n: usize = args[5].parse().expect("bad length");
            let ks = RatchetEngine::new(&key, &nonce, epoch_bytes, DEFAULT_N_MAPS).keystream(n);
            println!("{}", hex_of(&ks));
        }
        "aead_seal" => {
            // chaos_core aead_seal <key_hex> <nonce_hex> <aad_hex> <pt_hex> <n_maps>  -> blob hex
            let key = parse_hex_bytes(&args[2]);
            let nonce = parse_hex_bytes(&args[3]);
            let aad = parse_hex_bytes(&args[4]);
            let pt = parse_hex_bytes(&args[5]);
            let n_maps: usize = args[6].parse().expect("bad n_maps");
            println!("{}", hex_of(&aead_seal(&key, &nonce, &pt, &aad, n_maps)));
        }
        "aead_open" => {
            // chaos_core aead_open <key_hex> <aad_hex> <blob_hex> <n_maps>  -> plaintext hex or INVALID
            let key = parse_hex_bytes(&args[2]);
            let aad = parse_hex_bytes(&args[3]);
            let blob = parse_hex_bytes(&args[4]);
            let n_maps: usize = args[5].parse().expect("bad n_maps");
            match aead_open(&key, &blob, &aad, n_maps) {
                Some(pt) => println!("{}", hex_of(&pt)),
                None => println!("INVALID"),
            }
        }
        "stream_seal" => {
            // chaos_core stream_seal <key_hex> <salt_hex> <aad_hex> <n_maps> <chunk_hex>...
            let key = parse_hex_bytes(&args[2]);
            let salt = parse_hex_bytes(&args[3]);
            let aad = parse_hex_bytes(&args[4]);
            let n_maps: usize = args[5].parse().expect("bad n_maps");
            let chunk_vecs: Vec<Vec<u8>> = args[6..].iter().map(|a| parse_hex_bytes(a)).collect();
            let chunks: Vec<&[u8]> = chunk_vecs.iter().map(|v| v.as_slice()).collect();
            println!("{}", hex_of(&stream_seal(&key, &salt, &chunks, &aad, n_maps)));
        }
        "stream_open" => {
            // chaos_core stream_open <key_hex> <aad_hex> <n_maps> <blob_hex>  -> plaintext hex or INVALID
            let key = parse_hex_bytes(&args[2]);
            let aad = parse_hex_bytes(&args[3]);
            let n_maps: usize = args[4].parse().expect("bad n_maps");
            let blob = parse_hex_bytes(&args[5]);
            match stream_open(&key, &blob, &aad, n_maps) {
                Some(pt) => println!("{}", hex_of(&pt)),
                None => println!("INVALID"),
            }
        }
        "ratchet_aead_seal" => {
            // chaos_core ratchet_aead_seal <master_hex> <nonce_hex> <aad_hex> <n_maps>
            //     <inner_nonce_hex> <pt_hex> [<inner_nonce_hex> <pt_hex> ...]
            // Drives a sender session through the messages (index 0,1,2,...); prints each wire blob
            // hex, space-separated. Each message takes its own explicit inner nonce.
            let master = parse_hex_bytes(&args[2]);
            let nonce = parse_hex_bytes(&args[3]);
            let aad = parse_hex_bytes(&args[4]);
            let n_maps: usize = args[5].parse().expect("bad n_maps");
            let rest = &args[6..];
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
        "ratchet_aead_open" => {
            // chaos_core ratchet_aead_open <master_hex> <nonce_hex> <aad_hex> <n_maps> <wire_hex>...
            // Drives a receiver session over the wires in order; prints each plaintext hex
            // space-separated, or "INVALID" for the whole run if ANY message fails to open.
            let master = parse_hex_bytes(&args[2]);
            let nonce = parse_hex_bytes(&args[3]);
            let aad = parse_hex_bytes(&args[4]);
            let n_maps: usize = args[5].parse().expect("bad n_maps");
            let mut receiver = RatchetAeadReceiver::new(&master, &nonce, &aad, n_maps);
            let mut outs: Vec<String> = Vec::new();
            let mut ok = true;
            for w in &args[6..] {
                let wire = parse_hex_bytes(w);
                match receiver.open(&wire) {
                    Some(pt) => outs.push(hex_of(&pt)),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                println!("{}", outs.join(" "));
            } else {
                println!("INVALID");
            }
        }
        "twolock_seal" => {
            // chaos_core twolock_seal <master_hex> <outer_nonce_hex> <inner_nonce_hex> <aad_hex>
            //     <pt_hex> <inner_alg> <n_maps>  -> two-locks blob hex (or INVALID for an unknown alg)
            // inner_alg: aes-256-gcm | chacha20-poly1305. Both nonces are explicit so the KAT can pin them.
            let master = parse_hex_bytes(&args[2]);
            let outer_nonce = parse_hex_bytes(&args[3]);
            let inner_nonce = parse_hex_bytes(&args[4]);
            let aad = parse_hex_bytes(&args[5]);
            let pt = parse_hex_bytes(&args[6]);
            let alg = parse_inner_alg(&args[7]);
            let n_maps: usize = args[8].parse().expect("bad n_maps");
            match twolock_seal(&master, &outer_nonce, &inner_nonce, &pt, &aad, alg, n_maps) {
                Some(blob) => println!("{}", hex_of(&blob)),
                None => println!("INVALID"),
            }
        }
        "twolock_open" => {
            // chaos_core twolock_open <master_hex> <aad_hex> <blob_hex> <n_maps>  -> plaintext hex or INVALID
            // The inner cipher is self-describing (read from the authenticated inner blob), so it is not given.
            let master = parse_hex_bytes(&args[2]);
            let aad = parse_hex_bytes(&args[3]);
            let blob = parse_hex_bytes(&args[4]);
            let n_maps: usize = args[5].parse().expect("bad n_maps");
            match twolock_open(&master, &blob, &aad, n_maps) {
                Some(pt) => println!("{}", hex_of(&pt)),
                None => println!("INVALID"),
            }
        }
        "dh_public" => {
            // chaos_core dh_public <private_hex>  -> g^private mod p as 256-byte hex (or INVALID)
            let private = parse_hex_bytes(&args[2]);
            match dh_public(&private) {
                Some(p) => println!("{}", hex_of(&p)),
                None => println!("INVALID"),
            }
        }
        "dh_raw_shared" => {
            // chaos_core dh_raw_shared <private_hex> <peer_public_hex>  -> raw g^(ab) 256-byte hex or INVALID
            let private = parse_hex_bytes(&args[2]);
            let peer = parse_hex_bytes(&args[3]);
            match dh_raw_shared(&private, &peer) {
                Some(s) => println!("{}", hex_of(&s)),
                None => println!("INVALID"),
            }
        }
        "dh_shared_key" => {
            // chaos_core dh_shared_key <private_hex> <peer_public_hex> <info_hex>  -> 32-byte key hex or INVALID
            let private = parse_hex_bytes(&args[2]);
            let peer = parse_hex_bytes(&args[3]);
            let info = parse_hex_bytes(&args[4]);
            match dh_shared_key(&private, &peer, &info) {
                Some(k) => println!("{}", hex_of(&k)),
                None => println!("INVALID"),
            }
        }
        "mlkem_ek" => {
            // chaos_core mlkem_ek <seed_hex>  -> 1184-byte encapsulation key hex (or INVALID)
            let seed = parse_hex_bytes(&args[2]);
            match mlkem_ek_from_seed(&seed) {
                Some(ek) => println!("{}", hex_of(&ek)),
                None => println!("INVALID"),
            }
        }
        "mlkem_encapsulate" => {
            // chaos_core mlkem_encapsulate <ek_hex> <m_hex>  -> "<ct_hex> <ss_hex>" or INVALID
            let ek = parse_hex_bytes(&args[2]);
            let m = parse_hex_bytes(&args[3]);
            match mlkem_encapsulate(&ek, &m) {
                Some((ct, ss)) => println!("{} {}", hex_of(&ct), hex_of(&ss)),
                None => println!("INVALID"),
            }
        }
        "mlkem_decapsulate" => {
            // chaos_core mlkem_decapsulate <seed_hex> <ct_hex>  -> 32-byte shared secret hex or INVALID
            let seed = parse_hex_bytes(&args[2]);
            let ct = parse_hex_bytes(&args[3]);
            match mlkem_decapsulate(&seed, &ct) {
                Some(ss) => println!("{}", hex_of(&ss)),
                None => println!("INVALID"),
            }
        }
        "hybrid_combine" => {
            // chaos_core hybrid_combine <classical_hex> <pq_hex> <info_hex> <dh_a_hex> <dh_b_hex>
            //     <kem_pk_a_hex> <kem_ct_hex>  -> 32-byte hybrid session key hex
            let classical = parse_hex_bytes(&args[2]);
            let pq = parse_hex_bytes(&args[3]);
            let info = parse_hex_bytes(&args[4]);
            let dh_a = parse_hex_bytes(&args[5]);
            let dh_b = parse_hex_bytes(&args[6]);
            let kem_pk_a = parse_hex_bytes(&args[7]);
            let kem_ct = parse_hex_bytes(&args[8]);
            let key = hybrid_combine(&classical, &pq, &info, &dh_a, &dh_b, &kem_pk_a, &kem_ct);
            println!("{}", hex_of(&key));
        }
        "hybrid_respond" => {
            // chaos_core hybrid_respond <dh_private_b_hex> <dh_peer_a_hex> <kem_pk_a_hex> <m_hex> <info_hex>
            //     -> "<dh_b_public_hex> <kem_ct_hex> <key_hex>" or INVALID
            let dh_private_b = parse_hex_bytes(&args[2]);
            let dh_peer_a = parse_hex_bytes(&args[3]);
            let kem_pk_a = parse_hex_bytes(&args[4]);
            let m = parse_hex_bytes(&args[5]);
            let info = parse_hex_bytes(&args[6]);
            match hybrid_respond(&dh_private_b, &dh_peer_a, &kem_pk_a, &m, &info) {
                Some((dh_b, ct, key)) => {
                    println!("{} {} {}", hex_of(&dh_b), hex_of(&ct), hex_of(&key))
                }
                None => println!("INVALID"),
            }
        }
        "hybrid_initiator_key" => {
            // chaos_core hybrid_initiator_key <dh_private_a_hex> <kem_seed_hex> <dh_peer_b_hex>
            //     <kem_ct_hex> <info_hex>  -> 32-byte session key hex or INVALID
            let dh_private_a = parse_hex_bytes(&args[2]);
            let kem_seed = parse_hex_bytes(&args[3]);
            let dh_peer_b = parse_hex_bytes(&args[4]);
            let kem_ct = parse_hex_bytes(&args[5]);
            let info = parse_hex_bytes(&args[6]);
            match hybrid_initiator_key(&dh_private_a, &kem_seed, &dh_peer_b, &kem_ct, &info) {
                Some(k) => println!("{}", hex_of(&k)),
                None => println!("INVALID"),
            }
        }
        "benchmm" => {
            // chaos_core benchmm <n_maps> <mbytes>  -> throughput of the REAL shipped combiner.
            let n_maps: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(DEFAULT_N_MAPS);
            let mb: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(64);
            let n = mb * 1024 * 1024;
            let mut eng = MultiMapEngine::new(b"bench-master-key", b"bench-nonce", n_maps);
            let _ = eng.keystream(1 << 16); // warm
            let t0 = Instant::now();
            let mut sink: u64 = 0;
            let mut produced = 0usize;
            while produced < n {
                let chunk = eng.keystream(1 << 20);
                for b in &chunk {
                    sink ^= *b as u64;
                }
                produced += chunk.len();
            }
            let dt = t0.elapsed().as_secs_f64();
            let mbps = (produced as f64 / (1024.0 * 1024.0)) / dt;
            eprintln!("checksum {sink}");
            println!("{n_maps}-map: {mbps:.2} MB/s  ({mb} MB in {dt:.3}s)");
        }
        "bench" => {
            let mb: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(64);
            let n = mb * 1024 * 1024;
            let mut eng = ChaosEngine::new(
                0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210_FEDC_BA98_7654_3210,
                0xA5A5_A5A5,
            );
            // warm a little, then time
            let _ = eng.keystream(1 << 16);
            let t0 = Instant::now();
            let mut sink: u64 = 0;
            let mut produced = 0usize;
            while produced < n {
                let chunk = eng.keystream(1 << 20);
                for b in &chunk {
                    sink ^= *b as u64;
                }
                produced += chunk.len();
            }
            let dt = t0.elapsed().as_secs_f64();
            let mbps = (produced as f64 / (1024.0 * 1024.0)) / dt;
            eprintln!("checksum {sink}"); // keep the optimizer honest
            println!("{mbps:.2} MB/s  ({mb} MB in {dt:.3}s)");
        }
        "timing" => {
            // Constant-time probe: does the per-byte step time depend on the SECRET?
            // Each key gets a different secret control parameter -> different break-point p / (HALF-p),
            // the very values the OLD hardware divide leaked. We time ns/byte for many keys and report
            // the spread (max-min)/mean. A small spread = timing independent of the secret = no leak.
            let keys: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(64);
            let bytes_per_key = 1 << 20; // 1 MB per key
            let reps = 15; // min over reps = each key's true compute floor (noise only adds time)
            // deterministic spread of controls across the whole valid p-band
            let mut times: Vec<f64> = Vec::with_capacity(keys);
            for k in 0..keys {
                // vary the control parameter widely and oddly so p lands all over [MIN_P, HALF-MIN_P]
                let control = (k as u128)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15_1234_5678_9ABC_DEF1)
                    .wrapping_add(0xA5A5_A5A5_5A5A_5A5A);
                let mut best = f64::INFINITY;
                for _ in 0..reps {
                    let mut eng = ChaosEngine::new(0xDEAD_BEEF, control, 0xC0FFEE);
                    let _ = eng.keystream(1 << 14); // warm
                    let t0 = Instant::now();
                    let chunk = eng.keystream(bytes_per_key);
                    let dt = t0.elapsed().as_secs_f64();
                    let mut sink = 0u64;
                    for b in &chunk {
                        sink ^= *b as u64;
                    }
                    std::hint::black_box(sink);
                    let ns_per_byte = dt * 1e9 / bytes_per_key as f64;
                    if ns_per_byte < best {
                        best = ns_per_byte; // min-of-reps = the clean run, least disturbed by noise
                    }
                }
                times.push(best);
            }
            // Robust spread: each key's value is already its min-of-reps (true compute floor, since
            // OS/cache noise can only ADD time). If timing leaked the secret, these floors would
            // systematically differ. Report median and a percentile-based spread (p95-min)/median so a
            // single scheduler hiccup can't masquerade as a leak — the same lesson as the ratchet seam.
            times.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let median = times[times.len() / 2];
            let lo = times[0];
            let p95 = times[(times.len() * 95 / 100).min(times.len() - 1)];
            let hi = times[times.len() - 1];
            let spread = (p95 - lo) / median * 100.0;
            println!(
                "keys={keys}  ns/byte floors: min {lo:.3}  median {median:.3}  p95 {p95:.3}  max {hi:.3}"
            );
            println!(
                "secret-dependent spread (p95-min)/median: {spread:.2}%  (small = no key-dependent timing)"
            );
        }
        _ => {
            eprintln!("usage: chaos_core ks <seed> <control> <nonce> <n>");
            eprintln!("       chaos_core from_master <key_hex> <nonce_hex> <n>");
            eprintln!("       chaos_core multimap <key_hex> <nonce_hex> <n_maps> <n>");
            eprintln!("       chaos_core ratchet <key_hex> <nonce_hex> <epoch_bytes> <n>");
            eprintln!("       chaos_core aead_seal <key_hex> <nonce_hex> <aad_hex> <pt_hex> <n_maps>");
            eprintln!("       chaos_core aead_open <key_hex> <aad_hex> <blob_hex> <n_maps>");
            eprintln!("       chaos_core stream_seal <key_hex> <salt_hex> <aad_hex> <n_maps> <chunk_hex>...");
            eprintln!("       chaos_core stream_open <key_hex> <aad_hex> <n_maps> <blob_hex>");
            eprintln!("       chaos_core ratchet_aead_seal <master_hex> <nonce_hex> <aad_hex> <n_maps> <inner_nonce_hex> <pt_hex>...");
            eprintln!("       chaos_core ratchet_aead_open <master_hex> <nonce_hex> <aad_hex> <n_maps> <wire_hex>...");
            eprintln!("       chaos_core twolock_seal <master_hex> <outer_nonce_hex> <inner_nonce_hex> <aad_hex> <pt_hex> <inner_alg> <n_maps>");
            eprintln!("       chaos_core twolock_open <master_hex> <aad_hex> <blob_hex> <n_maps>");
            eprintln!("       chaos_core dh_public <private_hex>");
            eprintln!("       chaos_core dh_raw_shared <private_hex> <peer_public_hex>");
            eprintln!("       chaos_core dh_shared_key <private_hex> <peer_public_hex> <info_hex>");
            eprintln!("       chaos_core mlkem_ek <seed_hex>");
            eprintln!("       chaos_core mlkem_encapsulate <ek_hex> <m_hex>");
            eprintln!("       chaos_core mlkem_decapsulate <seed_hex> <ct_hex>");
            eprintln!("       chaos_core hybrid_combine <classical_hex> <pq_hex> <info_hex> <dh_a_hex> <dh_b_hex> <kem_pk_a_hex> <kem_ct_hex>");
            eprintln!("       chaos_core hybrid_respond <dh_private_b_hex> <dh_peer_a_hex> <kem_pk_a_hex> <m_hex> <info_hex>");
            eprintln!("       chaos_core hybrid_initiator_key <dh_private_a_hex> <kem_seed_hex> <dh_peer_b_hex> <kem_ct_hex> <info_hex>");
            eprintln!("       chaos_core bench <mbytes>");
            eprintln!("       chaos_core benchmm <n_maps> <mbytes>");
            eprintln!("       chaos_core timing <keys>");
            std::process::exit(2);
        }
    }
}
