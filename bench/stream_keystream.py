"""
Stream the SHIPPED keystream as raw bytes to stdout — the feeder for PractRand.

PractRand's `RNG_test stdin` consumes a raw byte stream and reports at every power-of-two
checkpoint (8 MB, 16 MB, 32 MB, ...). We pipe this generator into it:

    python3 bench/stream_keystream.py ratchet | RNG_test stdin -tlmax 256MB -multithreaded

WHICH PATH (argv[1]):
  ratchet   the real shipped stream: 4-map engine UNDER the auto-rekey ratchet (re-keys every
            64 KiB). This is what a user actually gets, and it exercises the re-key seams — the
            most likely place a flaw would surface. DEFAULT.
  multimap  the raw 4-map XOR keystream with no ratchet (isolates the combiner itself).

argv[2] (optional): max MiB to emit, then stop cleanly. Omit / 0 = run until the consumer closes
the pipe. Key/nonce are fixed so the run is reproducible.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _harness import build_multimap, build_ratchet  # noqa: E402

KEY = b"practrand-heavy-randomness-key"
NONCE = b"practrand-heavy-randomness-nonce"
CHUNK = 1 << 16   # 64 KiB per write


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "ratchet"
    max_mib = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    eng = build_ratchet(KEY, NONCE) if which == "ratchet" else build_multimap(KEY, NONCE)

    out = sys.stdout.buffer
    written = 0
    limit = max_mib * 1024 * 1024
    try:
        while True:
            out.write(eng.keystream(CHUNK))
            written += CHUNK
            if limit and written >= limit:
                break
    except BrokenPipeError:
        pass   # the consumer (PractRand) stopped — normal, clean exit
    finally:
        try:
            out.flush()
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
