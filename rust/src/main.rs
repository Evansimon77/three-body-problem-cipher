//! CLI for the chaos core.
//!
//!   chaos_core ks   <seed> <control> <nonce> <n>   -> prints n keystream bytes as hex
//!   chaos_core bench <mbytes>                       -> generates that many MB, prints MB/s
//!
//! <seed>/<control>/<nonce> accept decimal or 0x-hex (up to 127 bits). The `ks` mode is what
//! tests/test_rust_parity.py calls to compare against kat/vectors.json.

use std::time::Instant;

use chaos_core::ChaosEngine;

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
            let mut out = String::with_capacity(n * 2);
            for b in ks {
                out.push_str(&format!("{:02x}", b));
            }
            println!("{out}");
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
        _ => {
            eprintln!("usage: chaos_core ks <seed> <control> <nonce> <n>");
            eprintln!("       chaos_core bench <mbytes>");
            std::process::exit(2);
        }
    }
}
