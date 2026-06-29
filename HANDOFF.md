# HANDOFF — chaos-cipher · 2026-06-29
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Start **Phase 8.5 — port the classical + PQ-hybrid key-agreement to Rust** (`keyexchange.py` +
`pq_keyexchange.py`). Working tree is clean and everything is saved/pushed on branch `phase6-two-locks`
(8.4 = commit `d4994b6`). First confirm green with the "Run / verify" block, then build 8.5 the same way
8.1–8.4 were built (port → KAT vector → parity + interop → full verify, zero new clippy).

## Goal
Build the most-secure version of an UNVETTED research chaos stream cipher, deployed only as the OUTER
wall over a vetted vault ("Option B"). Standing rule: best/most-secure path, never the easy one; every
feature is BUILT **and** attacked/measured. The user wants the system **complete, extensible, and fast**,
and asked to implement ALL the remaining technologies. Current big effort: **Phase 8 — finish the fast
Rust core so it mirrors every Python capability**, in value-order (speed-critical bulk path first).

## State
- **Saved & pushed (branch `phase6-two-locks`):**
  - Phase 6 two-locks (`twolock.py`) — `912202c`/`e9a4fb6`. Authenticated PQ handshake
    (`auth_pq_keyexchange.py`) — `93b63bc`.
  - **Phase 8.1** committing AEAD + **8.2** streaming AEAD — `ff9ab1e`. **8.3** ratchet session AEAD —
    `5057d54`. All ride existing `hmac`/`sha2` crates (no new deps).
  - **Phase 8.4 two-locks wrapper** — commit **`d4994b6`**. Rust `twolock_seal`/`twolock_open` (port of
    twolock.py): HKDF-SHA256 key split (independent outer/inner keys), inner vault = AES-256-GCM default
    or ChaCha20-Poly1305 (self-describing alg byte), outer chaos AEAD over the inner blob. CLI
    `twolock_seal`/`twolock_open`. **ADDED vetted crates `hkdf`, `aes-gcm`, `chacha20poly1305`** (the
    handoff had planned only aes-gcm+hkdf; chacha was added for full Python parity/interop — trimmable to
    AES-only if minimal is preferred). `twolock` KAT vector for BOTH inner ciphers; parity + Python↔Rust
    interop both ways.
- **In flight:** nothing half-edited. Clean stop right after the save. **Next concrete task = 8.5.**
- **Verified at save:** Rust **13/13**; Python suite **171**; parity/kat/fuzz **29**; all 6 attack scripts
  PASS; ruff clean; **zero NEW clippy** (only the 2 documented cosmetic notes); KAT diff proved only the
  `twolock` block was added (every keystream vector byte-identical → Rust contract intact); Python↔Rust
  interop works for two-locks (AES + ChaCha).
- **Blocked / open:** none technical. The cipher stays UNVETTED by design (Phase 7 = external review).

## Next steps (Phase 8 remaining — value-order)
1. **8.5 classical + PQ-hybrid key-agreement** — port `keyexchange.py` (big-int Diffie–Hellman) +
   `pq_keyexchange.py` (classical DH + vetted ML-KEM-768). Needs an ML-KEM crate, e.g. RustCrypto
   `ml-kem` or `aws-lc-rs`. Add a deterministic KAT vector (pin any randomness, like 8.4 pinned both
   nonces), CLI modes, parity + interop. Completeness, not speed (handshakes run once per session).
2. **8.6 authenticated PQ handshake** — port `auth_pq_keyexchange.py` (ML-DSA crate). Last item;
   completeness only. Then Phase 7 (external review) is the only remaining roadmap item.

## Key files
- `PROGRESS.md` — living compass; read first. Roadmap + dated DONE log (folded into the top status line;
  newest = Phase 8.4).
- `rust/src/lib.rs` — Rust core. Keystream engines + aead/stream/ratchet_aead/**twolock** sections near
  the end (before `#[cfg(test)] mod tests`). 8.5 goes here (a new key-agreement section).
- `rust/src/main.rs` — CLI bridge; add new modes here (pattern: parse hex args → call lib → print hex).
  `parse_inner_alg` shows the name→id helper pattern.
- `rust/Cargo.toml` — deps. 8.4 added `hkdf`, `aes-gcm`, `chacha20poly1305`. 8.5 adds an ML-KEM crate.
- `kat/generate_kat.py` — recomputes ALL KAT vectors; add the new deterministic vector here, then
  regenerate with `python3 kat/generate_kat.py --write`. The docstring's "covered" list goes 1–10
  (twolock = 10); add 11 for key-agreement.
- `kat/vectors.json` — frozen contract. Keystream blocks must stay byte-identical when you add a new one.
- `tests/test_rust_parity.py` — add parity + Python↔Rust interop tests for each ported layer (twolock
  tests at the end are the latest template).
- Python sources being ported: `aead.py`/`commit.py`/`streaming.py`/`ratchet_aead.py`/`twolock.py` (all
  DONE), `keyexchange.py`+`pq_keyexchange.py` (8.5), `auth_pq_keyexchange.py` (8.6).
- `THREAT_MODEL.md` — threat table; update when a phase adds/closes a property.

## Don't-trip wires
- **Cipher is UNVETTED** — never on real data. Every new file says so; keep that framing. The shells ride
  vetted HMAC/SHA/AES/ChaCha/HKDF/ML-KEM/ML-DSA; only the chaos keystream is hand-rolled.
- **KAT discipline (critical):** snapshot `vectors.json` BEFORE regenerating, then DIFF to prove ONLY the
  intended new block was added and every keystream vector is byte-identical (the Rust contract). One-liner:
  `python3 -c "import json;a=json.load(open('/tmp/before.json'));b=json.load(open('kat/vectors.json'));print([k for k in a if a[k]!=b.get(k)], [k for k in b if k not in a])"`
- **Determinism for KAT:** the Python shells use random nonces/salts/ephemerals. For a KAT/parity vector,
  pin them (8.1 fixed a 16-byte nonce; 8.2 added `salt=`; 8.4 added keyword-only `inner_nonce=`/
  `outer_nonce=` to twolock.py and forwarded the outer one to aead.seal's `nonce=`). For 8.5 the DH/KEM
  ephemerals will need the same treatment (a seeded/explicit ephemeral path for the vector only).
- **HKDF salt=None ⇄ Rust `Hkdf::new(None, ikm)`** — matches Python's `HKDF(salt=None)` (zeros of hashlen);
  proven by the twolock interop test. Reuse `hkdf_sha256_key` in lib.rs.
- **clippy disambiguation:** the twolock section brings `aead::KeyInit` into crate scope, so the two HMAC
  helpers use `<HmacSha256 as Mac>::new_from_slice` to disambiguate. Keep that if you touch them.
- **Rust is NOT on PATH** (installed `--no-modify-path`). Prefix cargo with `. "$HOME/.cargo/env" &&`.
- **`rust/target/` and `docs/` are gitignored** (`docs/` holds a real N.I.E. — never commit it).
- **Two pre-existing cosmetic clippy notes** (lib.rs:149 weak-param check, main.rs:20 parse_hex_bytes) —
  documented as left-as-is. Don't let them read as new. Introduce ZERO new clippy warnings.
- **Save = decide-and-do** (the global smart-checkpoint skill, not a fixed script). When the user says
  "save": back up only if there's unsaved work (git commit+push → prepend dated Obsidian `## 📜 Build Log`
  entry in `~/Documents/Cursor Code/Obsidian Vault/Vault/Chaos Cipher.md` → fold the DONE update into
  PROGRESS.md's top status line), refresh HANDOFF.md only if a fresh session is likely next, end with a
  big-letters next step. Don't offer it as a menu. Tests are NOT part of save. "force save" = guaranteed
  full backup.
- **`cryptography` 49.0.0 + OpenSSL 3.5** provide ML-KEM + ML-DSA in Python; PQ tests auto-skip if absent.
- The user prefers plain, no-jargon, SHORT reports (explain like to a smart non-programmer; one picture
  for hard ideas). Recommend honestly even when told "do it all"; flag deviations from the plan.

## Run / verify
```bash
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher"
. "$HOME/.cargo/env" && (cd rust && cargo build --release && cargo test --release)   # Rust 13/13
python3 -m pytest tests/ -q                                                          # Python 171 pass
for a in commitment streaming ratchet_aead pq_hybrid twolock auth_pq; do echo -n "$a: "; python3 attacks/${a}_attack.py | tail -1; done
python3 -m ruff check .                                                              # clean
. "$HOME/.cargo/env" && (cd rust && cargo clippy --release --all-targets)            # only the 2 old notes
# KAT contract + parity + interop:
python3 -m pytest tests/test_rust_parity.py tests/test_kat.py tests/test_rust_fuzz.py -q
```
