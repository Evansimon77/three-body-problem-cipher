# HANDOFF — chaos-cipher · 2026-06-29
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Start **Phase 4 ratchet port**: port `ratchet.py` (auto-rekey one-way key chain) to Rust as a
`RatchetEngine` over the existing `MultiMapEngine`, then verify it bit-identical to the frozen
ratchet KAT vector. First action: open `rust/src/lib.rs` (read `MultiMapEngine` + `kdf_hash`) and
re-read `ratchet.py` — the construction is below under "Don't-trip wires".

## Goal
Make the chaos cipher usable (the speed blocker) AND constant-time by porting the hot loop to Rust.
The cipher stays an UNVETTED research artifact — never on real data; eventual deployment is only as
the OUTER wall over a vetted vault ("Option B"). Standing directive: best/most secure version, not
whatever's easiest. Every roadmap item is BUILT **and** attacked/measured.

## State
- **Done (Phase 4 so far, all on branch `branchless-core`, all saved/pushed):**
  - **Stage A** (commit `55309fa`): Rust `chaos_core` crate ports the per-byte single engine. Bit-
    identical to KAT, ~43× faster than Python (~74 MB/s).
  - **Stage B** (commit `a1e7b22`): replaced the per-step big-int divide-by-secret with a Barrett-style
    **precomputed reciprocal** → **timing-leak #2 CLOSED**. Measured 0.41% timing spread across 128
    secret keys (`chaos_core timing`). Bit-identical KAT 3/3; reciprocal vs big-int oracle 0 mismatches
    over ~4.8M pairs. Speed flat ~75 MB/s — the win was constant-time, NOT throughput.
  - **Stage C** (commit `5dbacdf`, latest): ported `from_master` (seed KDF) + `MultiMapEngine` (4-map
    XOR combiner) with real **SHA-512** (`sha2` crate). Rust now makes the REAL shipped keystream.
    Bit-identical to KAT for from_master, multimap n=1, n=4. Parity 6/6, full suite 91/91.
- **In flight:** nothing half-edited — Stage C was saved at a clean stop. The ratchet port hasn't
  started; `ratchet.py` was just read. Working tree should be clean (verify `git status`).
- **Blocked / open:** none. The timing leak is closed; the only-single-engine gap is closed.

## Next steps
1. **Port the ratchet** to Rust (`RatchetEngine` in `rust/src/lib.rs`). It needs **HMAC-SHA256** —
   add the `hmac` crate (alongside `sha2`); `_kdf(key,label) = HMAC-SHA256(key,label)`. Mirror the
   chain exactly (see Don't-trip wires for the byte-precise construction).
2. Add a CLI mode `chaos_core ratchet <key_hex> <nonce_hex> <epoch_bytes> <n>` → keystream hex.
3. **Verify** bit-identical to the frozen ratchet KAT vector (key `chaos-kat-master-key-v1`, nonce
   `chaos-kat-nonce-v1`, epoch_bytes 32, length 80). Wire a new case into `tests/test_rust_parity.py`
   (the KAT vector crosses ≥2 re-key seams — that's the point).
4. Re-run `cargo test --release`, `python3 -m pytest tests/ -q` (must stay 91+/91+ and parity 7/7).
5. Add `zeroize` to wipe the burned chain key in place (the Python ratchet can only drop the ref).
   Update `THREAT_MODEL.md` §4 (zeroization → closed) + `CONSTANT_TIME.md` note. Then `/save`.
6. Later in Phase 4: parallelize the 4 maps + CTR; benchmark the shipped stream vs AES/ChaCha;
   differential fuzz Rust==KAT.

## Key files
- `PROGRESS.md` — living compass; read first. Roadmap + dated DONE log (newest = Stage C).
- `ratchet.py` — the Python ratchet to mirror (HMAC-SHA256 one-way chain, re-key per epoch, burn key).
- `multimap.py` / `engine.py` — already ported; the references for the KDF + engine.
- `rust/src/lib.rs` — the Rust core. Has `ChaosEngine` (incl. `from_master`, constant-time `div_step`
  via `reciprocal`/`select`), `MultiMapEngine`, `kdf_hash`, `derive_seed_control`. Add `RatchetEngine` here.
- `rust/src/main.rs` — CLI: `ks`, `from_master`, `multimap`, `bench`, `timing`. Add `ratchet` mode.
- `rust/Cargo.toml` — deps `ruint`, `sha2`. Add `hmac`.
- `kat/vectors.json` — frozen contract. `ratchet` key holds the vector to match. Regenerate via
  `kat/generate_kat.py --write` (DON'T — it's frozen; only the Rust side should change).
- `tests/test_rust_parity.py` — runs the Rust binary vs the KAT; auto-skips if unbuilt. 6 cases now.
- `CONSTANT_TIME.md`, `THREAT_MODEL.md` — contract docs to update after the ratchet/zeroize lands.

## Don't-trip wires
- **Ratchet construction (byte-exact — get this right or the KAT won't match):**
  - `_V = b"chaos-ratchet-v1|"`; `_kdf(key,label) = HMAC-SHA256(key,label).digest()` (32 bytes).
  - K_0 = `_kdf(master_key, _V + b"init|" + nonce)`.
  - Per epoch i (idx = `i.to_bytes(8,"big")`): epoch_key MK_i = `_kdf(chain_key, _V+b"epoch|"+idx)`;
    next chain K_{i+1} = `_kdf(chain_key, _V+b"chain|"+idx)`; then chain_key = next (burn K_i).
  - The epoch's engine = `MultiMapEngine(MK_i, nonce + b"|ep|" + idx, n_maps)`. NOTE the epoch nonce
    is the ORIGINAL nonce bytes with `|ep|<idx>` appended — feed THAT into the multimap KDF.
  - Re-key every `epoch_bytes` bytes; `_advance()` is called on entry to epoch 0 too.
  - `n_maps` defaults to 4 (`DEFAULT_N_MAPS`); `epoch_bytes` default 64 KiB but the KAT uses 32.
- **Rust is NOT on PATH** (installed `--no-modify-path`). Prefix every cargo/rust command with
  `. "$HOME/.cargo/env" &&`. Rust 1.96, toolchain at `~/.cargo` + `~/.rustup`.
- **`rust/target/` is gitignored**; `Cargo.lock` IS committed. **`docs/` is gitignored** (holds a real
  N.I.E.) — never put specs/output there.
- **192-bit → u128 reduction:** the SHA-512 KDF yields 192-bit seed_key/control; reduce mod M / mod
  HALF (via U256) BEFORE `ChaosEngine::new` — idempotent with the engine's own `% M`/`% HALF`, so it
  stays bit-identical. `derive_seed_control` already does this; the ratchet reuses `MultiMapEngine`.
- **div_step precondition is num ≤ den+1**, not num ≤ den — region 3 at x==HALF gives den+1. The
  reciprocal is built exact across that range; don't "tighten" it back to num ≤ den.
- **Save = 3 steps** (project CLAUDE.md): git commit+push → prepend Obsidian `## 📜 Build Log` entry
  in `~/Documents/Cursor Code/Obsidian Vault/Vault/Chaos Cipher.md` → update `PROGRESS.md`. Tests are
  NOT part of save — run pytest separately. Save only when the user says "save".
- **Honest framing always:** still UNVETTED; the port's job is bit-identity + constant-time, not a
  security proof. Report speed losses/leaks plainly (Stage B gained no speed — said so).

## Run / verify
```bash
. "$HOME/.cargo/env"
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/rust"
cargo build --release && cargo test --release        # Rust unit tests (4 now)
cd ..
python3 -m pytest tests/ -q                           # full Python suite (91 pass; parity needs the build)
python3 -m pytest tests/test_rust_parity.py -v        # KAT parity (6/6 now; add ratchet → 7/7)
rust/target/release/chaos_core timing 128             # constant-time probe (~0.41% spread)
rust/target/release/chaos_core multimap <key_hex> <nonce_hex> 4 64   # the real shipped keystream
```
