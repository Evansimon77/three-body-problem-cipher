"""
Speed benchmark — honest tradeoff numbers vs vetted primitives.

Compares the chaos engine's throughput (MB/s) against AES-256-CTR and ChaCha20 from the
`cryptography` library (hardware-accelerated, C). Sets realistic expectations for the
"computational overhead" caveat in the original write-up.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine  # noqa: E402


def bench(label, fn, nbytes):
    t0 = time.time()
    fn(nbytes)
    dt = time.time() - t0
    mbps = (nbytes / (1024 * 1024)) / dt if dt else float("inf")
    print(f"  {label:24s}: {mbps:8.2f} MB/s  ({dt*1000:7.1f} ms for {nbytes//1024} KB)")
    return mbps


def chaos(nbytes):
    DiscreteChaoticEngine(0x123456789ABCDEF, 0xFEDCBA987654321, nonce=1).keystream(nbytes)


def main():
    nbytes = 256 * 1024  # 256 KB; chaos engine is pure-Python so keep it modest
    print(f"Throughput (encrypting {nbytes//1024} KB of zeros):\n")
    c = bench("chaos PWLCM (pure-Py)", chaos, nbytes)

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        key = os.urandom(32)
        iv = os.urandom(16)

        def aes(n):
            enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
            enc.update(b"\x00" * n)

        def chacha(n):
            enc = Cipher(algorithms.ChaCha20(key, os.urandom(16)), None).encryptor()
            enc.update(b"\x00" * n)

        big = 16 * 1024 * 1024  # these are fast; give them more data for a stable number
        a = bench("AES-256-CTR (lib)", aes, big)
        ch = bench("ChaCha20 (lib)", chacha, big)
        print(f"\n  chaos is ~{a/c:,.0f}x slower than AES-256-CTR, "
              f"~{ch/c:,.0f}x slower than ChaCha20.")
    except ImportError:
        print("\n  (install `cryptography` for the AES/ChaCha baseline: "
              "pip install cryptography)")


if __name__ == "__main__":
    main()
