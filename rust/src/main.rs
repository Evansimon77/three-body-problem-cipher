//! CLI for the chaos core.
//!
//!   chaos_core ks   <seed> <control> <nonce> <n>   -> prints n keystream bytes as hex
//!   chaos_core bench <mbytes>                       -> generates that many MB, prints MB/s
//!
//! <seed>/<control>/<nonce> accept decimal or 0x-hex (up to 127 bits). The `ks` mode is what
//! tests/test_rust_parity.py calls to compare against kat/vectors.json.

use std::time::Instant;

use chaos_core::{ChaosEngine, MultiMapEngine, RatchetEngine, DEFAULT_N_MAPS};

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
            eprintln!("       chaos_core bench <mbytes>");
            eprintln!("       chaos_core timing <keys>");
            std::process::exit(2);
        }
    }
}
