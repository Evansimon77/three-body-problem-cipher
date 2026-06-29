# HANDOFF — chaos-cipher · 2026-06-29
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Start **Phase 8.3 — port the ratchet session AEAD (`ratchet_aead.py`) to Rust.** Working tree is clean
and everything is saved/pushed on branch `phase6-two-locks`. First confirm green with the "Run / verify"
block, then build 8.3 the same way 8.1/8.2 were built (port → KAT vector → parity + interop → verify).

## Goal
Build the most-secure version of an UNVETTED research chaos stream cipher, deployed only as the OUTER
wall over a vetted vault ("Option B"). Standing rule: best/most-secure path, never the easy one; every
feature is BUILT **and** attacked/measured. The user wants the system **complete, extensible, and fast**,
and asked to implement ALL the remaining technologies. Current big effort: **Phase 8 — finish the fast
Rust core so it mirrors every Python capability**, in value-order (speed-critical bulk path first).

## State
- **Saved & pushed (branch `phase6-two-locks`):**
  - Phase 6 two-locks (`twolock.py`) — commits `912202c`/`e9a4fb6`.
  - Authenticated PQ handshake (`auth_pq_keyexchange.py`) — commit `93b63bc`. Hybrid confidentiality
    (DH+ML-KEM-768) + hybrid authentication (triple-DH static binding AND ML-DSA-65 signatures).
    `attacks/auth_pq_attack.py` 6/6.
  - **Phase 8.1** Rust committing AEAD (full seal/open) + **8.2** Rust streaming AEAD — commit `ff9ab1e`.
    CLI: `aead_seal`/`aead_open`/`stream_seal`/`stream_open`. `aead`+`stream` KAT vectors added; keystream
    contract proven intact. Both use existing `hmac`/`sha2` crates — no new deps.
  - Docs (PROGRESS.md) — commit `8098853`.
- **In flight:** nothing half-edited. Clean stop right after the save. **Next concrete task = 8.3.**
- **Verified at save:** Python suite **162 pass**; Rust unit tests **8/8**; parity/kat/fuzz green;
  ruff clean; zero new clippy warnings; Python↔Rust interop works for AEAD + streaming.
- **Blocked / open:** none technical. The cipher stays UNVETTED by design (Phase 7 = external review).

## Next steps (Phase 8 remaining — value-order)
1. **8.3 ratchet session AEAD** — port `ratchet_aead.py` to Rust: one-way HMAC chain over the committing
   AEAD (8.1). The Rust `RatchetEngine` (keystream ratchet) already exists; this is the *session-AEAD*
   layer on top. Add a `ratchet_aead` KAT vector (deterministic), CLI modes, parity + interop. No new deps.
2. **8.4 two-locks wrapper** — port `twolock.py`: chaos outer AEAD over a vetted **AES-256-GCM** inner +
   HKDF key split. ADDS Rust crates (`aes-gcm`, `hkdf`). This is where the new-dependency phase starts.
3. **8.5 classical + PQ-hybrid key-agreement** — port `keyexchange.py` + `pq_keyexchange.py` (big-int DH
   + ML-KEM crate, e.g. RustCrypto `ml-kem` or `aws-lc-rs`).
4. **8.6 authenticated PQ handshake** — port `auth_pq_keyexchange.py` (ML-DSA crate). Last; completeness,
   no speed gain (handshakes run once per session).
   Then: Phase 7 (external review) is the only remaining roadmap item.

## Key files
- `PROGRESS.md` — living compass; read first. Roadmap + dated DONE log (newest = Phase 8.1/8.2).
- `rust/src/lib.rs` — Rust core. Keystream (ChaosEngine/MultiMapEngine/RatchetEngine) + NEW aead/stream
  sections near the end (before `#[cfg(test)] mod tests`). 8.3 goes here.
- `rust/src/main.rs` — CLI bridge; add new modes here (pattern: parse hex args → call lib → print hex).
- `kat/generate_kat.py` — recomputes ALL KAT vectors; add the new deterministic vector here, then
  regenerate with `python3 kat/generate_kat.py --write`.
- `kat/vectors.json` — frozen contract. Keystream blocks (finalize/engine_raw/from_master/multimap/
  ratchet) are the Rust keystream contract — must stay byte-identical when you add a new block.
- `tests/test_rust_parity.py` — add parity + Python↔Rust interop tests for each ported layer.
- Python sources being ported: `aead.py`, `commit.py` (done), `streaming.py` (done), `ratchet_aead.py`
  (8.3), `twolock.py` (8.4), `keyexchange.py`/`pq_keyexchange.py` (8.5), `auth_pq_keyexchange.py` (8.6).
- `THREAT_MODEL.md` — threat table; update when a phase adds/closes a property.

## Don't-trip wires
- **Cipher is UNVETTED** — never on real data. Every new file says so; keep that framing. The shells ride
  vetted HMAC/SHA/AES/ML-KEM/ML-DSA; only the chaos keystream is hand-rolled.
- **KAT discipline (critical):** after adding a vector + regenerating `vectors.json`, DIFF to prove ONLY
  the intended new block was added and every keystream vector is byte-identical (the Rust contract). The
  one-liner used at save:
  `python3 -c "import json;a=json.load(open('/tmp/before.json'));b=json.load(open('kat/vectors.json'));print([k for k in a if a[k]!=b.get(k)], [k for k in b if k not in a])"`
- **Determinism for KAT:** the Python shells use random nonces/salts. For a KAT/Rust parity vector, pin
  the nonce/salt (8.1 used a fixed 16-byte nonce; 8.2 added an optional `salt=` arg to streaming.py).
  Mirror that for 8.3 (the ratchet_aead session likely needs a fixed salt/nonce path too).
- **Rust is NOT on PATH** (installed `--no-modify-path`). Prefix cargo with `. "$HOME/.cargo/env" &&`.
- **`rust/target/` and `docs/` are gitignored** (`docs/` holds a real N.I.E. — never commit it).
- **Two pre-existing cosmetic clippy notes** (lib.rs:149 weak-param check, main.rs:19 parse_hex_bytes) —
  documented as left-as-is. Don't let them read as new. Introduce ZERO new clippy warnings.
- **Save = 3 steps**, ONLY when the user says "save": git commit+push → prepend dated Obsidian `## 📜
  Build Log` entry in `~/Documents/Cursor Code/Obsidian Vault/Vault/Chaos Cipher.md` → update PROGRESS.md.
  Tests are NOT part of save.
- **`cryptography` 49.0.0 + OpenSSL 3.5** provide ML-KEM + ML-DSA in Python; PQ tests auto-skip if absent.
- The user prefers plain, no-jargon reports (explain like to a smart non-programmer; one picture for hard
  ideas). Recommend honestly even when told "do it all" (8.5/8.6 add deps for completeness, not speed).

## Run / verify
```bash
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher"
. "$HOME/.cargo/env" && (cd rust && cargo build --release && cargo test --release)   # Rust 8/8
python3 -m pytest tests/ -q                                                          # Python 162 pass
for a in commitment streaming ratchet_aead pq_hybrid twolock auth_pq; do echo -n "$a: "; python3 attacks/${a}_attack.py | tail -1; done
python3 -m ruff check .                                                              # clean
# KAT contract + parity + interop:
python3 -m pytest tests/test_rust_parity.py tests/test_kat.py tests/test_rust_fuzz.py -q
```
