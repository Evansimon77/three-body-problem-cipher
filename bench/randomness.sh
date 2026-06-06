#!/usr/bin/env bash
# Dump keystream to a file and run external randomness batteries if installed.
# Always runs the pure-Python NIST-lite screen (zero deps).
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-/tmp/chaos_keystream.bin}"
MB="${2:-10}"

echo "==> Dumping ${MB} MB of keystream to ${OUT}"
python3 - "$OUT" "$MB" <<'PY'
import sys
from engine import DiscreteChaoticEngine
out, mb = sys.argv[1], int(sys.argv[2])
eng = DiscreteChaoticEngine(0xDEADBEEFCAFEF00D1357, 0x2468ACE13579, nonce=99)
with open(out, "wb") as f:
    chunk = bytearray()
    for _ in range(mb * 1024 * 1024):
        chunk.append(eng.generate_byte())
        if len(chunk) >= 65536:
            f.write(chunk); chunk = bytearray()
    f.write(chunk)
print("   done")
PY

echo; echo "==> Pure-Python NIST-lite screen"
python3 bench/nist_lite.py

echo; echo "==> ent (if installed)"
if command -v ent >/dev/null 2>&1; then ent "$OUT"; else echo "   ent not found (brew install ent)"; fi

echo; echo "==> dieharder (if installed; slow, needs >100MB ideally)"
if command -v dieharder >/dev/null 2>&1; then
  dieharder -a -g 201 -f "$OUT" || true
else
  echo "   dieharder not found (brew install dieharder)"
fi
