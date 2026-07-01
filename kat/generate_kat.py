"""
KAT generator — produces the FROZEN known-answer test vectors (§3 of the roadmap).

WHY THIS EXISTS
---------------
A known-answer test (KAT) is a locked list of "this exact input must produce this exact
output." Once frozen, it is the contract the cipher can never silently break:

  * REGRESSION GUARD (today, Python): any edit that changes a single output byte fails
    tests/test_kat.py. Refactors that are meant to be behaviour-preserving are PROVEN so;
    accidental behaviour changes are caught the moment they happen.
  * PORT ORACLE (Phase 4, Rust): the Rust core is "done" only when it reproduces every
    vector here bit-for-bit. The KAT turns "I think the port matches" into "it provably
    matches" — the same role NIST's KATs play for AES/SHA implementations.

WHAT IS COVERED — every DETERMINISTIC layer the port must reproduce, bottom-up:
  1. finalize     — the nonlinear ARX output mixer (finalize), the trickiest bit-math.
  2. engine_raw   — the integer PWLCM core keystream from fixed (seed, control, nonce),
                    including the all-zero key edge (exercises the init avalanche + dead-state).
  3. from_master  — the hash-KDF seeding path the AEAD layers actually use.
  4. multimap     — the shipped N-map XOR combiner (n_maps = 1 and the default 4).
  5. ratchet      — the shipped auto-rekey stream, with a TINY epoch so the vector crosses
                    two re-key seams (proves the seam math is frozen too).
  6. siv          — the fully deterministic AEAD (seal_siv), a full-stack end-to-end vector.
  7. aead         — the committing AEAD (aead.seal), full stack, with its nonce PINNED for the KAT.
  8. stream       — the streaming AEAD (seal_stream), multi-chunk self-delimiting blob, salt pinned.
  9. ratchet_aead — the forward-secret SESSION AEAD, a 3-message session crossing two chain seams.
  10. twolock     — the two-locks wrapper: chaos OUTER wall over a VETTED inner vault (AES-256-GCM
                    and ChaCha20-Poly1305), HKDF key-split, both nonces pinned.
  11. keyexchange — classical Diffie-Hellman over RFC 3526 MODP-2048 (g^a, g^b, g^(ab), the KDF key),
                    secret exponents pinned. Pure integer pow + hashlib, no chaos engine, no ML-KEM.
  12. pq_hybrid   — the post-quantum hybrid handshake: classical DH mixed with ML-KEM-768 via the
                    SP 800-56C combiner. The ML-KEM ciphertext is pinned as frozen test data (encaps is
                    randomised in Python's API, like NIST's own ML-KEM KATs); both backends DECAPSULATE
                    it to the same secret, and the combiner is a pure SHA-512 over the secrets+transcript.
  13. auth_pq     — the AUTHENTICATED post-quantum handshake (auth_pq_keyexchange.py): vector 12's
                    confidentiality PLUS mutual identity proof — triple-DH static binding combined with
                    ML-DSA-65 signatures. The two 1952-byte ML-DSA verifying keys are pinned as frozen
                    test data (keygen is deterministic from the 32-byte seed; both backends reproduce
                    them). The transcript and session key are pure SHA-512 over the secrets, so this whole
                    vector reproduces WITHOUT the ML-DSA backend. Signatures are NOT pinned — they never
                    enter the key, and Python signs hedged while Rust signs deterministically, yet both
                    verify — so the round-trip + interop tests cover the signing/verification path.

Anything random by design (a fresh nonce/salt drawn per call) is pinned via a keyword-only KAT hook
so it has a fixed answer here; in real use those default to fresh randomness. Round-trip + attack
tests cover the non-frozen behaviour.

USAGE
-----
    python3 kat/generate_kat.py            # print the vectors as JSON to stdout
    python3 kat/generate_kat.py --write    # (re)write kat/vectors.json  -- FREEZING ACTION

Regenerating with --write is a deliberate, reviewed act: it re-freezes the contract to the
CURRENT code. Do it only when you INTEND to change the cipher's output (and say so in the
commit). Never run it just to make a failing test pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aead import tag  # noqa: E402
from commit import key_commitment  # noqa: E402
from engine import finalize, M, DiscreteChaoticEngine  # noqa: E402
from keyexchange import P, DHParty  # noqa: E402
from pq_keyexchange import (  # noqa: E402
    MLKEM_AVAILABLE, _combine, _transcript, mlkem,
)
from auth_pq_keyexchange import (  # noqa: E402
    PQ_AVAILABLE as MLDSA_AVAILABLE,
    PublicIdentity as AuthPublicIdentity,
    _combine as _auth_combine,
    _transcript as _auth_transcript,
    mldsa as _auth_mldsa,
)
from multimap import MultiMapEngine  # noqa: E402
from ratchet import RatchetEngine  # noqa: E402
from ratchet_aead import SenderSession  # noqa: E402
from siv import seal_siv  # noqa: E402
from streaming import seal_stream  # noqa: E402
from twolock import seal_twolock  # noqa: E402

VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")

# Fixed, arbitrary-but-pinned inputs. These are PUBLIC test inputs, not secrets.
_KEY_INT = 0x0123456789ABCDEF0123456789ABCDEF  # gitleaks:allow — public KAT test input, not a secret
_CTRL_INT = 0xFEDCBA9876543210FEDCBA9876543210
_NONCE_INT = 0xA5A5A5A5
_KEY_BYTES = b"chaos-kat-master-key-v1"
_NONCE_BYTES = b"chaos-kat-nonce-v1"

# --- Phase 8.5 frozen ML-KEM-768 test data (PUBLIC, not secret). ML-KEM encapsulation is randomised in
# Python's high-level API, so — exactly as NIST's own ML-KEM KAT files do — we PIN the ciphertext as
# frozen test data. Both Python (OpenSSL 3.5) and Rust (RustCrypto `ml-kem`) DECAPSULATE it to the
# identical 32-byte secret; that shared, deterministic decapsulation is the portable contract. The seed
# and encaps message derive from fixed labels; the encapsulation key + ciphertext + decapsulated secret
# were produced once by the Rust deterministic encapsulation and are frozen here so this generator runs
# WITHOUT the ML-KEM backend (e.g. on an older OpenSSL). When the backend IS present, compute_vectors()
# self-checks these constants below so they can never silently drift.
_MLKEM_EK_HEX = "e0ec065a4ab9832598f285ce17132c08311f5ab79b0aa272cc7a530f5551abd7503c1773fda0bc551cbefcf3352ad2cb50099b69868bd818c92f4ca4d30971b7d4796fb5a8e355b87620356542543b34cc9f633cdc9984d7466ff4391905ba98185631b37294d6308c12dc51961b3733da00fb50650ef8b7bda19b24c10983937c9dfaa56931668659a966907423b145e7cc090e982b562366a343cdf1a42b7f546159c8539d70cfa89933688c83ad5a4a36d03cde007c854354c6a18ef885a3bd4b3970399b083170110b4a06a1c37b656e5a1056f127b8cd6cb6212ba27b0cc681093c74a760d7055233e2954a3674f611c370e826bd7108d93338842a448769af323a2e4ac67111e0b1ed1cad0c0c8967744c751046e749689cfb4da3b697c10002bfb14e89116d09bcbef1cc7841294fedea4218f9098ed925e7bc8060567e8fd9b12c94b2020c9d321026a3195801e0a53c1acb08c933722861a6144832d9506e3c63072802cc1b91614339edb8b01cf1a2f86ab436477767db4c94e15064613997caab28ec78377759fec599955598c1bb7537c8bff298c6080c9d26e772f88916805c07ee7806f3f9075f733dd705802784a2b3c28c362ac097119efad173a3b10c410166a30832ff347e5be2347258748b8a855ab30a03fc258729c97b4ba1dd0b43f48b00bd934626c879b00749f61a6e509bb2128c4ca2ca80d7582c91f18a2788121a4949bcc140050959aea69e06e25c8e12142cb29c75068bfb348aa2786c75d892e276742b935948154ae2b6228638849eec760f778cc3721fee08307d295cbec546e9e540254425210477394922a9bb5d6293a520e7c041cb63d042c59d82b91df20583d9bc4c6abc327431f7b0baeda28f69b177b79b8229379c17f6bca581119d69a221c2231cca038c187449b03a272508e374179e6c247f8b427e818ba86668791c2162a7252e3b95f02634419a264bc941c9d43b9aca7a5312a7c567c5782371407612f911457ef981ce092edfb95080c02762d2acda2a7dfcfa97ddd34f6cb1a60ca98031731bd672270c363773e85ce4c69facb120463225a4b4b374ca7820d08031d875cb88a6116c32674bbaed13a4d443830ff34e6d30b69da2427294ce45a698611b3928a0260260a05bc28cdb563afae515020a5a2ba5be3d05847bdc9fb091b82a84348023240b454ffc2542e5216a03016cd52c0bb0e0521c117320f45c0e426ec8daa4fb6c6b4149bbbea6024c59042840aa2dd8bdfb12a3c7b403f769514f4b62765c424484ac92f97a2d780b1dd84ebb152b7f8c5083439e1baa29d892309936bdd9851ee3e2181dfc4ecd9a12be6349c0526c1b74427189acb632c59e98900500b26cfa7c91395bfac757b0ec08abfa6a2071491ca8ae64e11a6695058d8805d3e030dbe323ec520f8a56b54fb22a28a1a29e118e3cf485559c9ddd5b6eaae651643a53e3c89b1b2a3af22827690a266c78c23700a4df4591df527f5002c3888905d342150b49a8412883cf155de2552dab5b97f6c90d7c7cb759d977850921917622c95b0763956f0232ac3d71bbbb02c020c809ef4274d43c0d72f2ccb24682c8c81c76733da2769d5d660f795c1ecbbd19b673e15b06773f3c8f79f8f728a95a361c4744a2948d680c5b52222c66"
_MLKEM_CT_HEX = "09d2ad465bf9925cfd322a773f9d2639d326cd7924129dc7c5a6b46ce8284a290c20ecd4181c120430727f99f68940bd3761f913878baa858603fededa32df0c940e5c19cbdeacbb6f428c0d655467fe5115a563c83f19f8b9c86270ba0ef02a46a36179580e47f0078f12688e11a70cfa58dcda6caec626479f02d6ed01b537376584e1b897502ea3705e3974df9c50c738ce828ea32917974cca632b1881f2ec79f3cb60628ffe12ba59c22b117b9846c713433870adb9f98526931704a43ef4682f95a4b60446890d61f995aaba2040b695fee85aaa756724f72318320936557710cc0a5062569199e700df81004143db7d1ae99ad9a6f2f587563b00b2f2bd53fe9485f890c02db273e9de6f5cd8fbc7267caecb1a0041a4cff5eb1948453d4ac8b99d577912e338c14a60c3344cebfdd7df1d37f90788565e3c87f5d0b82cca6318e5e1c0f1a9d388cded06840bc0e520f7d7262205740c29372bb9b7b22efe852e8479889c91ced6d0db7d30eb809cfa3bf49501842ca05406016675e54311f20cb27015229f19d0737e233aabec6308d58c4299e237f0f34a3ea9f9275f48d8def26522c151ece82360185b1b67c08617a797d51465358bcbb157f5e2e08f153f8c4f9d8f127d38c698f5d0d8cc3a3ce061d7e3faa97a1b01186f28a8c47ec04befc00e3b377db94a05954db29136ecdc31b91291ec908ecc2b5c9943392904f01a18ec9296bab26b5836abb29970a4f815f4cfc8af50ff55977ea600014250dfc42c79c7d40eb4e1313d1c841abfb892fa9f3f4681f177c63c502b2429f2f3bac3d00d271b356444b0e7484a530056a708d9e8fa07d134f3068bb142a90cbd571f9f562a5124eb6da1db1e37106bde4ce9e41d28388ffcb0c87466ab4e9bba3c90caaa23d396918a04d083722b8e9668fec5663de483f21f30cffbf84adc3e33a7e5ad0c36d21e09f745dd34bf307db77d5ed8f6f33532004db7d6b31ea3c97ad02c29babe213e97d2b6c3936ff5492164c5589f15ca8b0e4dced7138e6ccb6ccb7df574c59b663a0122b1d2e229c51c14289d15824e3fad6900f444940075b852605f609d503b6edcb3cc686166a39fd54a2b4691a8025834cadf3c33b298f1f8f39aab34a446c52f6bb480ed22d0d446d1e5ecfde9ae3779b81699dd2b37fffd2283d20819d72a5db5600432cd4b2c9ec6a4512be8cda9981248825251b54bf30ad3f9ae6e55cdbede55d79fc44413e1587e87ba11f029cf4d61ee283ec607f7de2f2153703ecb43ce2cbe14551bd859da8bfb0c49ed0fc0c841956873b164b2f725d3df66b6f66196d684322133f7e37c0224d1111079ab928d90443fca438ec4650fc9ac5b2cb849707a3170c2f3c1275428832bb8bf1597bc8895a8105928895a6e143b941cf69f0ad39106fd080a4b5b14ec6cf5feacbe55165ae4dcc9d56cf94934cc3f618dec7b9f5e1ae09a7551136f8d7dda0620deae36043978d1997711b7fd3f5790e7ff5572c4a7e2b3c6876e92d446f6e71fa35762"
_MLKEM_PQ_SECRET_HEX = "f84276c2b40b92bc77c508c1929a0ca0d9dbf18bc868f7e6a9e4ce283a7e879d"

# --- Phase 8.6 frozen ML-DSA-65 verifying keys (PUBLIC, not secret). ML-DSA keygen is DETERMINISTIC from
# the 32-byte seed, so unlike the ML-KEM ciphertext these are not "randomised" — but we still pin them as
# frozen test data so this generator (and the auth_pq vector below) runs WITHOUT the ML-DSA backend. Each is
# from_seed_bytes(sha256("...sig-seed-{a,b}-v1")).public_key().public_bytes_raw(). When the backend IS
# present, compute_vectors() self-checks them against the seed so they can never silently drift. The
# signatures themselves are NOT frozen: they never enter the session key, and Python signs hedged while Rust
# signs deterministically, so both verify but neither is a fixed value — the round-trip tests cover them.
_MLDSA_A_PUB_HEX = "402af588500a90739238c0e485f0553b12dbe88a65fd8d86e925691f2742aea606d1e0e856384c05850e29b08b27ce727ee5937d8eac82254cfde6947ad0a9d1d91279f2b488798d1fda430977757b4d976c2859a73d27eca2dece1e25fd68b0d276973e3fc59f9383fffa04523c78579a09f3ebddce158ca6a81614bd904bdf40fdc09e7e5efe3d9ceb9c6ae2cfecc95a5e775052f0c8cd2694b69f127446f8e4fdce88cf952835e91c3974dd9de50f6edff40ea74ba6c528ab6f0a70ce99e946fcd950f0d28f60e743596eb9a810c814ad19b0895a875b2c36d4cfd3ecba4ca6fb4fa657236252f1929f48be03a6148d489012910cbea5b1d3e0ecc1f2f8926dbd93c4c506676905f0a64ddb3f70bf967d426b1c8e9b493007ed29872ff8fbae45f5c5b0c30dcb3452b01a9fe1a171b1355e2687e3860491185f7c33965e010727920a6ed2fca1b62311af65ffe96fe38209e22d6dcbee139612c981e5d9c822400734aa7e14fef70ea2765ffc946ed7c330ce54529a56e673b2cbc42367728dc2f68fe3c8900b29456702e59a7bff1d701c4058bde1d79e742d49034df6c12fb7e346cce81142ed40e9b33734e8157b200d97b177cff66eed6b56ee614a25da2112b4e06c64fd30b3681990fabdac7e37bb58241893cc3336d002c939f023a0151d5c452b257dd4dcfd30c2ac132282d964adca67405c15ed49cd6219ec68c73be8c8038fdc218054382cae4a20bd31ee0c868f94a31150f98a9c67bed71e809486c1379e839dea33335d1985312a492c3b54fe0e16c89a297679c62be898544a59b977e838cfb70c7b2e076647de5ce009284a8cb09a50796f720a0ac10cdfea800ff9f5ec51b37d4c2e92094612fe44c1b283737f26a26f4b39cbadeb42b63457b98bc5f5665dd5955b9a5ed8a0ea53cad52aeb6b39e56a0a54b9c5356a519a002af4151cc6b796cd9547f4507c0c564a9709e57ff23c9c5d73fe0dd341354d5f876575fb053c1b38aa4ccb5f5108019045a1ed5114da0541460f3c906a7193b21b885f0696457412bde1438bad209fae935d3d83e8f19aab141e0aea0523ee8db74afae429d913443a03b389af93ef4a9f2fea9397620c1351b81ff7c15de60c4225ac0a477a40dd18fe6fe15102040fa808251930e75b83a9c9f64b8ffefaa05704678b6a9b1a07fd113be7829d9eaa073edbaa6c364cd2d02033cc6041d1a972a008fa21ebbecb34ea5ae280166bf187eb342de9e61fda1e1801eaad8fcf132ed62cbca2705514e88e0687e51d60123a58fcd77763989cc41f36fef7a9f07e816f5a125bb6c8934fc710ed1110489ff4115f7d779b947d7d88c360f8467a6a1835a5dbef8d6156093cf04679cd81d49af855c1b0ec91dd1da7f7dc9b72518450f9193507093ae2985c320c396e2df94cf62204c20e6925d17f248df3e5244388d5688a387de9c62d13ccf8ccee5de9e5479347afd386bbe2a63a6b07388acec6de28cfdec8d32c053b5fbd3f278dfaeec6ad74da22782cc6e90885bc094356f35a9afdf98b23caf8f80012b994fcfcd9232e603327a9e564b7b42470f55b3b2e08a91d19e536458be2ea272949b3d9abd2967eff68dc8cd009c0950857001fb6f68804cb14a8a237848fe32edadf983dcb65a5dbb8a03956ced0628ab352c719d57ad62bbd3ace7c7ce46843d85a0f91c96a168279e3f9ae0e0d384367f8d5868d18a4218dfa18eb6716d8fb766f737371d07213816ac26142db410f6a77bf7a71c6ff829a82081564b78467291a921d127ef9ee78bd2f73910f77a9a70cf979254273ce0ca0a7769698e71fc99781c06b2bf67faa35a601489978a43fd1fb7ab10375b0b635b2290c36e293dc241140f96c36d3ace0a0cd3548634a50bfc1395abbc2a05181b6c4a8ed1ef69e0446a9aafcd8654c60217273659e587aff012705429b3a28ffbcf893a28b3d3d21d9fa05a0f7e9dc1586b2bff4e8810ba2100992809d0c101670826f7682ac4fd27f7e54c7d8df3da68f15f1f98f4f40e17fa8fd90c1b338ad7afd349d9961b81664aeb6462dd63492ed5dd6b75b8e156bca90df1703edc51c9ace6b168600da10d4ec62fb9b59a70a2a626531f16c51fe1e9c0d70ac15f36ba057aee733d376a509483102aecc50043d3302987eda37a4c4c19c0cc00bb4ea82e57636757ba5896cfba73a0ae1c16e5907c280c0295ba95712ae8dd6e26fdb1e184c08d717f8e5d1a6f18e0f06cb617ad2cb33dba4f8d729ae5cda5bc1b5796dab5474fc650af091296dfba507cceabf28ef67c35083d13b4f28a43c1fb5068a2c9d1fcaa2af4cbf451f0a1cac4b6a4dda2841e5090cfe8bc5251db12665629e89bbc71bdb6debb8cf3bd88a7a967b544a48ae2ce609a5e5a19a2934c142e45abe99704c5dbd86811a01000dd6ad0cfc7b6db7bfd438d399b7d7234b29462ccd169abe8db9ab6558175bad1319e3426caa5a93c3938be6509abeff6df063dec2914e7e076ac9c72bb7c851be2ec52f8d0ed78dff8c1d7d93a84b18c64473ecdd1e1c77b33b521707a63d8ffdfa02b14f045317147f0a90695bee5292f439a072f1c1f32b037ecdd27227159a3993cf0aa106226063a20051b41ed3da8a4039b5dac1812b3af8bf5544a5286d2b060cf30f1cae3aa7af45dd74cf4e6281a29397b45b15955cb981502e4c2d292f5f619ba3a2c41fc7906bebef98ac4f5f5b2c05e56c8afc7041252b9d67199e355fd75dfa47d9668d"
_MLDSA_B_PUB_HEX = "7ec6ed776c9bd83fe7041d77fa8a6bdf473480d3cb9e65cc1a39a558edad066289cb9576e40f81f8faeb76539a8b709cae0edef8abb428ea78f32c0d3cc44dfe337bbeeae660814d41d08003c75928c79aec7aba96c7d0a305297d526848fa558fefa132e64c08c5a62afdc7233b3863e49c7da0fb1283a1030a556b15e256ea9b67ad46c54e7a5e568dcb8b8a9d9d205187d77283703d497a645588c74525ebc449214d943cb5806e6ec1da434e091dd00ad9d3caba7530d3937447ab9e0eb8194a2a90959250befae6ac4cf6471906a0cedcc33fb8bc4a357c94844b42355a195d7ac17b5d8a2530ad1b8d05d9bbf704cb33ccee56b70025aacd7e85083927036d90d5eba3299d438fb277c27469658769faf11fae522f3a2464739dc3c36fddad37dbe8ff191acb6c2440ad28c8e45af15edfae7f5b77992ecb2bc0ec2bf9c436c3d9a2b35d2cdc1a558d794d87e04e593b8ecca83ecde979ce68b64fda0bd468338874c5e60e55e256d1aa6c55e339466860d12d6afb95b107985d45b1e6d520911a8314dcce9312bfcc5c5a6e8c6e3e7e7196430d452899da408c6dd5989837afc11e08c08d4e9945de1fa8d0870f98fa86d96ac5e0129fbd7c92d7a30530d094eb5eb3ed4140375dd9c9526dbb48dcbaa7cf2a3174f912106a20212656e2e38a30cedffd98cfc46afa91d82d5ba02b05b2e4c2be2adfe376fe7cb3b6a266cd402e5738e759f22af252ba1fc68dabb42b90b7d8ac0d55a9d26530c43cbb70e1fcba5afe3a65e347b5e97ad31e2ca1a762bbce914b25ff5b41e900a368e9877194164ff70174840cf6c00ba117d668f98356f1f9477b4c49063ec3aa8ff09bb0628438d8fc45d686583f07393d389e5b6eba8e37c35ea384849c1be4832a4e24dc65ec564aa98f6ad70c4df6db3809b6000b1fe0a18ab48525656ff2e97d04b00e4b713f228c529e8583dec757cecbe19d7af73647c6344539b4c2496c00fd0be46805a042db812c41b22dd2d14b580223d5b542deee8dd982616f347c8670c5f4a8f41b81a47f423d8b973a90a83f904b5d59de0561345311be294b91f2116f669a8dbfee7b4a16efd08a9118d1754e1ecbfbcab29fc087898e562a3c74aa9a5bc1a83283ee261281a9cbfec27310179174cd017d1684f06c413a52f60e63b11c048cab8e6dc1d18892258991c1f927b6300b6ee97548f159fb530c304ab96dd5a109f264ad9b58d5c8dbfaeff781c13cfccece6f08ecf6c5358a7ed348416b4c0eb9bcb945c98605ab346f499ba68d8565a9f7d4fae2ae6a36ad522d8161da3d79296edbea03abe33a4daa5716b8469c52af8e2f74f02bbba2aa9fbb74f99feb7d75a73132b923350f00e45634417cb23fd512426aa808d9ee342fe2a5dc4f4535d1af66aeed33502767b805517e4a8d986602d042f21e82bdf2a1e0d15386017f71a37fff232cd7eb8af96cb6097cfc9f07ae22c6c8031a117992ce3e8a64056151ba363851f1da9d2db2f39b2dcb197afe9c246341c449f78a7acb52796b43b4202be4185100ab9fe41ba0ee9b5cb0f55b8c2188a3c4a884b993b6a9207558a2b752ed05bb4c3d63e45780b6685873f4b88050c17943d14f6ec203707e1857b1525df231c9a1a56582ba6d1036a8146216dcb2b6e06eea0efd1e0c08e37d4b7738a7df4929f73bb43aa82bcb23227d9941354d1eb130aea8a2d580e498f9f682f99063f50145117c3ef44a9909ef85891aae1acab927fee3f49f954c4cf0d40998d4fa6ff7504c23df7d80096770e2e5c840ba5592e6ad665c52a565997ec44cf53c26d7951183202348137ea7281587c78f632cfeb24afc7e32df3e6adb2eebe23ef00572059d6632342dba3bef404e4b361586f0368336875a5f14c4987e7aaa648f1fac101791180c5df5f444934d155f185ebc919339cee09bf4f716ebd0abac079c4d887e211c87cdf2bd88f6a7bf58e9c450e5cadcb781616ddb5e9cd7205e2c9fd597087a623f7142cca858a4a5369361d9e9216d2ba6c644c526a803c19d343c2886f5f20b5c92ec2165221ec2861337ab658426734d24b59e3143a63b3bea8181677827d0082f02b34c76667c60f6b5d0c94688e2f9c4103ea9a46c753c9d44e026543ed51e788267280235269fe9138eca80a409612428cdea792185c7174dadcf2745c2d12665d076140c837f1ca335270fc9513c7e678493cb7a62d98eebc20bafe2fd88d0fa84deb738e29f33d3d84a7a535ee53f6eea71cd716c5149a9f0900b836c5d192140596d5be15d6a373b8172a656af4d3f1d4e546a941d0c10e49e196c249cc8f17f2898f936d1c353864f3ec2aca9cbc5a2e64769d2b2da4e7883743b1027dc1e4106bab54e0393f9e5c8150b83314f9d9c127c9d4d663e85c49602fe07d8f10c1f9c49b0d4bb1eb6bd496794ec11d0c3d5d3eb7da648c6bd8098bcfb3c308e2cad42bfc6c3d6f1b3a8b553be2329085d316b7a9162a1f3ca33711cd4943f6f9f9aa377ed4f17be46e4b2b1be3b735138c8aa7c8a6a66c8760870657005a7c6f34d0d497f083b7b3c4f2e9ace986ea381e471a9c81b5bcbed1e6e8e6ab8ec64023687ad7a085fc84a136bbea7c432a22578306a7f2c2a9aa7ee551d8a57f094b8af3a288f34d709cc7385292fbe56c9bccc9cd842cb926177240e30b15a75a194027ed7f7a00ec6c457237fe0e6e4959ce174ef1b4861b567a254cbb9096ff891333a1cc7f17b7c2ddc42e265f206cb1a"


def compute_vectors() -> dict:
    """Recompute every KAT vector from the CURRENT code. The frozen vectors.json is a
    snapshot of this function's output; tests/test_kat.py compares the two."""
    v: dict = {"_meta": {
        "about": "Frozen known-answer vectors for the chaos PWLCM cipher. See generate_kat.py.",
        "modulus_M": hex(M),
    }}

    # 1. finalize — the nonlinear output mixer, across edge + interior states.
    finalize_inputs = [0, 1, 2, M - 1, M, M // 2, (1 << 64), (1 << 127) - 3,
                       0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF0123456789ABCDEF]
    v["finalize"] = [
        {"z": hex(z), "out": hex(finalize(z))} for z in finalize_inputs
    ]

    # 2. engine_raw — the bare PWLCM core. Includes the all-zero-key edge (init avalanche).
    raw_cases = [
        {"label": "typical", "seed": _KEY_INT, "control": _CTRL_INT, "nonce": _NONCE_INT},
        {"label": "all-zero-key", "seed": 0, "control": 0, "nonce": 0},
        {"label": "max-ish", "seed": M - 1, "control": M - 1, "nonce": M - 1},
    ]
    v["engine_raw"] = []
    for c in raw_cases:
        ks = DiscreteChaoticEngine(c["seed"], c["control"], c["nonce"]).keystream(64)
        v["engine_raw"].append({**c, "seed": hex(c["seed"]), "control": hex(c["control"]),
                                "nonce": hex(c["nonce"]), "keystream": ks.hex()})

    # 3. from_master — the hash-KDF seeding path used by the AEAD layers.
    ks = DiscreteChaoticEngine.from_master(_KEY_BYTES, _NONCE_BYTES).keystream(64)
    v["from_master"] = {"key": _KEY_BYTES.hex(), "nonce": _NONCE_BYTES.hex(), "keystream": ks.hex()}

    # 4. multimap — the shipped XOR combiner, single-map and the default 4-map.
    v["multimap"] = []
    for n in (1, 4):
        ks = MultiMapEngine(_KEY_BYTES, _NONCE_BYTES, n_maps=n).keystream(64)
        v["multimap"].append({"n_maps": n, "key": _KEY_BYTES.hex(),
                              "nonce": _NONCE_BYTES.hex(), "keystream": ks.hex()})

    # 5. ratchet — the shipped auto-rekey stream. epoch_bytes=32 so 80 bytes crosses TWO seams
    #    (at 32 and 64), freezing the re-key seam math, not just one epoch.
    ks = RatchetEngine(_KEY_BYTES, _NONCE_BYTES, epoch_bytes=32).keystream(80)
    v["ratchet"] = {"key": _KEY_BYTES.hex(), "nonce": _NONCE_BYTES.hex(),
                    "epoch_bytes": 32, "length": 80, "keystream": ks.hex()}

    # 6. siv — the fully deterministic AEAD, full stack end-to-end (siv || ciphertext).
    pt = b"known-answer plaintext for the deterministic SIV AEAD path."
    aad = b"kat-aad"
    blob = seal_siv(_KEY_BYTES, pt, aad)
    v["siv"] = {"key": _KEY_BYTES.hex(), "aad": aad.hex(),
                "plaintext": pt.hex(), "blob": blob.hex()}

    # 7. aead — the committing AEAD (aead.py), full stack end-to-end. seal() draws a RANDOM nonce, so
    #    here we build the identical blob with a FIXED nonce (its only nondeterminism) so the Rust port
    #    can pin a full encrypt/decrypt: nonce || commit || ciphertext || tag.
    aead_pt = b"known-answer plaintext for the committing AEAD path."
    aead_aad = b"kat-aead-aad"
    aead_nonce = b"chaos-kat-nonce1"          # 16 bytes, fixed for the KAT only
    aead_nmaps = 4
    aead_ct = MultiMapEngine(_KEY_BYTES, aead_nonce, n_maps=aead_nmaps).encrypt(aead_pt)
    aead_commit = key_commitment(_KEY_BYTES, aead_nonce, aead_aad)
    aead_tag = tag(_KEY_BYTES, aead_nonce, aead_commit, aead_aad, aead_ct)
    v["aead"] = {"key": _KEY_BYTES.hex(), "nonce": aead_nonce.hex(), "aad": aead_aad.hex(),
                 "plaintext": aead_pt.hex(), "n_maps": aead_nmaps,
                 "blob": (aead_nonce + aead_commit + aead_ct + aead_tag).hex()}

    # 8. stream — the streaming AEAD (streaming.py), multi-chunk, full self-delimiting blob. The salt
    #    is the only nondeterminism, so we pin it; the blob freezes the header, per-chunk framing,
    #    nonces and tags across several chunks (incl. the final-flag).
    stream_chunks = [b"first streaming chunk", b"second chunk, a bit longer than the first", b"3rd"]
    stream_aad = b"kat-stream-aad"
    stream_salt = b"chaos-kat-salt!!"        # 16 bytes, fixed for the KAT only
    stream_nmaps = 4
    stream_blob = seal_stream(_KEY_BYTES, stream_chunks, stream_aad,
                              n_maps=stream_nmaps, salt=stream_salt)
    v["stream"] = {"key": _KEY_BYTES.hex(), "salt": stream_salt.hex(), "aad": stream_aad.hex(),
                   "n_maps": stream_nmaps, "chunks": [c.hex() for c in stream_chunks],
                   "plaintext": b"".join(stream_chunks).hex(), "blob": stream_blob.hex()}

    # 9. ratchet_aead — the forward-secret SESSION AEAD (ratchet_aead.py). A 3-message session whose
    #    index advances 0->1->2, so the vector freezes the one-way chain across TWO seams (chain_0 ->
    #    chain_1 -> chain_2). The inner committing AEAD's nonce is the only nondeterminism, so we PIN
    #    one fixed inner nonce per message (safe: each message already has a unique chain-derived key).
    #    The blobs freeze the whole stack: chain init, per-message key derivation, index-bound aad, and
    #    the full committing-AEAD blob for each message.
    ra_master = _KEY_BYTES
    ra_session_nonce = b"chaos-kat-ra-non1"          # session nonce (feeds chain_0)
    ra_session_aad = b"kat-ra-session-aad"           # session-level aad
    ra_nmaps = 4
    ra_messages = [b"first session message", b"", b"third message, the final one here"]
    ra_inner_nonces = [b"ra-kat-nonce-000", b"ra-kat-nonce-001", b"ra-kat-nonce-002"]  # 16 bytes each
    ra_sender = SenderSession(ra_master, ra_session_nonce, aad=ra_session_aad)
    ra_wires = [ra_sender.seal(m, inner_nonce=n)
                for m, n in zip(ra_messages, ra_inner_nonces)]
    v["ratchet_aead"] = {"master": ra_master.hex(), "nonce": ra_session_nonce.hex(),
                         "aad": ra_session_aad.hex(), "n_maps": ra_nmaps,
                         "inner_nonces": [n.hex() for n in ra_inner_nonces],
                         "plaintexts": [m.hex() for m in ra_messages],
                         "wires": [w.hex() for w in ra_wires]}

    # 10. twolock — the two-locks wrapper (twolock.py): the chaos OUTER wall over a VETTED inner vault,
    #     keys split by HKDF-SHA256. We pin BOTH nonces (inner 12-byte, outer 16-byte) — the only
    #     nondeterminism. One blob per inner cipher (AES-256-GCM default + ChaCha20-Poly1305) freezes the
    #     whole stack end-to-end: HKDF key-split, the vetted inner AEAD, the self-describing alg byte, and
    #     the outer chaos AEAD over the inner blob. The outer wall uses the default 4 maps (twolock.py
    #     calls aead.seal without n_maps), so the Rust parity test passes n_maps=4 to match.
    tl_master = _KEY_BYTES
    tl_aad = b"kat-twolock-aad"
    tl_outer_nonce = b"chaos-kat-tl-non"          # 16 bytes (outer chaos AEAD nonce)
    tl_inner_nonce = b"tl-kat-non12"              # 12 bytes (inner vault nonce)
    tl_pt = b"two independent locks: a vetted vault inside the chaos wall."
    tl_blobs = {}
    for name in ("aes-256-gcm", "chacha20-poly1305"):
        blob = seal_twolock(tl_master, tl_pt, aad=tl_aad, inner=name,
                            inner_nonce=tl_inner_nonce, outer_nonce=tl_outer_nonce)
        tl_blobs[name] = blob.hex()
    v["twolock"] = {"master": tl_master.hex(), "outer_nonce": tl_outer_nonce.hex(),
                    "inner_nonce": tl_inner_nonce.hex(), "aad": tl_aad.hex(),
                    "plaintext": tl_pt.hex(), "n_maps": 4, "blobs": tl_blobs}

    # 11. keyexchange (DH) — classical Diffie-Hellman over RFC 3526 MODP-2048 (keyexchange.py). Both secret
    #     exponents are pinned, so the whole exchange is deterministic: g^a, g^b, the raw shared element
    #     g^(ab), and the SHA-512-derived 32-byte master key are frozen. Pure integer pow + hashlib (no
    #     chaos engine, no ML-KEM), so this vector reproduces on any machine.
    _DH_W = (P.bit_length() + 7) // 8                      # 256 bytes for the 2048-bit group
    kx_priv_a = int.from_bytes(hashlib.sha256(b"chaos-kat-dh-priv-a-v1").digest(), "big")
    kx_priv_b = int.from_bytes(hashlib.sha256(b"chaos-kat-dh-priv-b-v1").digest(), "big")
    kx_info = b"kat-dh-info"
    kx_a, kx_b = DHParty(kx_priv_a), DHParty(kx_priv_b)
    kx_raw = kx_a.raw_shared_secret(kx_b.public)
    v["keyexchange"] = {"private_a": kx_priv_a.to_bytes(32, "big").hex(),
                        "private_b": kx_priv_b.to_bytes(32, "big").hex(),
                        "public_a": kx_a.public.to_bytes(_DH_W, "big").hex(),
                        "public_b": kx_b.public.to_bytes(_DH_W, "big").hex(),
                        "raw_shared": kx_raw.hex(),
                        "info": kx_info.hex(),
                        "shared_key": kx_a.shared_key(kx_b.public, kx_info).hex()}

    # 12. pq_hybrid — the post-quantum hybrid handshake (pq_keyexchange.py): classical DH mixed with
    #     ML-KEM-768 through the SP 800-56C combiner. The ML-KEM ek/ct/secret are the frozen constants
    #     above (encaps is randomised in Python, so we pin them like NIST's ML-KEM KATs); both backends
    #     decapsulate the ciphertext to the same secret. The session key is a real hybrid: classical = the
    #     DH g^(ab) from vector 11, pq = the decapsulated secret, mixed by _combine over the full transcript
    #     (initiator DH, responder DH, initiator KEM pk, ciphertext). The combiner is pure SHA-512, so this
    #     whole vector reproduces WITHOUT the ML-KEM backend.
    pqh_seed = hashlib.sha512(b"chaos-kat-mlkem-seed-v1").digest()
    pqh_msg = hashlib.sha256(b"chaos-kat-mlkem-encaps-msg-v1").digest()
    pqh_ek = bytes.fromhex(_MLKEM_EK_HEX)
    pqh_ct = bytes.fromhex(_MLKEM_CT_HEX)
    pqh_pq_secret = bytes.fromhex(_MLKEM_PQ_SECRET_HEX)
    if MLKEM_AVAILABLE:                                    # self-check the frozen constants when we can
        _sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(pqh_seed)
        assert _sk.public_key().public_bytes_raw() == pqh_ek, "frozen ML-KEM ek drifted from the seed"
        assert _sk.decapsulate(pqh_ct) == pqh_pq_secret, "frozen ML-KEM ct/secret drifted"
    pqh_info = b"kat-pq-hybrid-info"
    pqh_transcript = _transcript(kx_a.public, kx_b.public, pqh_ek, pqh_ct)
    pqh_key = _combine(kx_raw, pqh_pq_secret, pqh_transcript, pqh_info)
    v["pq_hybrid"] = {"seed": pqh_seed.hex(), "encaps_msg": pqh_msg.hex(),
                      "ek": pqh_ek.hex(), "ct": pqh_ct.hex(), "pq_secret": pqh_pq_secret.hex(),
                      "classical": kx_raw.hex(), "info": pqh_info.hex(),
                      "dh_a": kx_a.public.to_bytes(_DH_W, "big").hex(),
                      "dh_b": kx_b.public.to_bytes(_DH_W, "big").hex(),
                      "transcript": pqh_transcript.hex(), "key": pqh_key.hex()}

    # 13. auth_pq — the AUTHENTICATED post-quantum handshake (auth_pq_keyexchange.py). Adds mutual identity
    #     proof on top of vector 12's confidentiality: a triple-DH STATIC binding (es, se) AND ML-DSA-65
    #     signatures over the transcript. Long-term identities are pinned by seeds: each party's ML-DSA
    #     verifying key (frozen above, deterministic from a 32-byte seed) plus a static classical DH key.
    #     The session ephemerals reuse vector 11's DH exponents (a, b) and the ML-KEM ephemeral reuses
    #     vector 12's frozen ek/ct/secret. The transcript binds BOTH identities + every public value, and
    #     the combiner mixes ee (=vector 11's g^(ab)), the ML-KEM secret, and the two static cross-terms
    #     es/se (sorted). All pure SHA-512 over integer-pow DH + the frozen secrets, so this whole vector
    #     reproduces WITHOUT the ML-DSA backend. Signatures are NOT pinned (they don't enter the key and
    #     Python signs hedged); the round-trip + interop tests verify the signing path.
    apq_a_sig_seed = hashlib.sha256(b"chaos-kat-mldsa-sig-seed-a-v1").digest()
    apq_b_sig_seed = hashlib.sha256(b"chaos-kat-mldsa-sig-seed-b-v1").digest()
    apq_a_static_priv = int.from_bytes(hashlib.sha256(b"chaos-kat-auth-static-a-v1").digest(), "big")
    apq_b_static_priv = int.from_bytes(hashlib.sha256(b"chaos-kat-auth-static-b-v1").digest(), "big")
    apq_a_sig_pub = bytes.fromhex(_MLDSA_A_PUB_HEX)
    apq_b_sig_pub = bytes.fromhex(_MLDSA_B_PUB_HEX)
    if MLDSA_AVAILABLE:                                    # self-check the frozen verifying keys when we can
        _a = _auth_mldsa.MLDSA65PrivateKey.from_seed_bytes(apq_a_sig_seed)
        _b = _auth_mldsa.MLDSA65PrivateKey.from_seed_bytes(apq_b_sig_seed)
        assert _a.public_key().public_bytes_raw() == apq_a_sig_pub, "frozen ML-DSA pub A drifted from its seed"
        assert _b.public_key().public_bytes_raw() == apq_b_sig_pub, "frozen ML-DSA pub B drifted from its seed"
    # static DH identity keys (pure integer pow) and the published PublicIdentity for each side
    apq_a_static = DHParty(apq_a_static_priv)
    apq_b_static = DHParty(apq_b_static_priv)
    apq_alice = AuthPublicIdentity(sig_public=apq_a_sig_pub, static_public=apq_a_static.public)
    apq_bob = AuthPublicIdentity(sig_public=apq_b_sig_pub, static_public=apq_b_static.public)
    # ephemerals reuse vector 11's DH pair (a=kx_a, b=kx_b); ML-KEM reuses vector 12's frozen ek/ct/secret
    apq_info = b"kat-auth-pq-info"
    apq_transcript = _auth_transcript(apq_alice, apq_bob, kx_a.public, pqh_ek, kx_b.public, pqh_ct)
    apq_ee = kx_raw                                       # DH(a_eph, b_eph) — same as vector 11's g^(ab)
    apq_es = kx_a.raw_shared_secret(apq_b_static.public)  # eph_A x STATIC_B
    apq_se = apq_a_static.raw_shared_secret(kx_b.public)  # STATIC_A x eph_B
    apq_key = _auth_combine(apq_ee, pqh_pq_secret, apq_es, apq_se, apq_transcript, apq_info)
    v["auth_pq"] = {"a_sig_seed": apq_a_sig_seed.hex(), "b_sig_seed": apq_b_sig_seed.hex(),
                    "a_static_priv": apq_a_static_priv.to_bytes(32, "big").hex(),
                    "b_static_priv": apq_b_static_priv.to_bytes(32, "big").hex(),
                    "a_eph_priv": kx_priv_a.to_bytes(32, "big").hex(),
                    "b_eph_priv": kx_priv_b.to_bytes(32, "big").hex(),
                    "a_sig_pub": apq_a_sig_pub.hex(), "b_sig_pub": apq_b_sig_pub.hex(),
                    "a_static_pub": apq_a_static.public.to_bytes(_DH_W, "big").hex(),
                    "b_static_pub": apq_b_static.public.to_bytes(_DH_W, "big").hex(),
                    "dh_i": kx_a.public.to_bytes(_DH_W, "big").hex(),
                    "dh_r": kx_b.public.to_bytes(_DH_W, "big").hex(),
                    "kem_seed": pqh_seed.hex(), "kem_m": pqh_msg.hex(),
                    "kem_pk_i": pqh_ek.hex(), "kem_ct": pqh_ct.hex(), "pq_secret": pqh_pq_secret.hex(),
                    "ee": apq_ee.hex(), "es": apq_es.hex(), "se": apq_se.hex(),
                    "info": apq_info.hex(),
                    "a_fingerprint": apq_alice.fingerprint(), "b_fingerprint": apq_bob.fingerprint(),
                    "transcript": apq_transcript.hex(), "key": apq_key.hex()}

    return v


def main() -> None:
    vectors = compute_vectors()
    if "--write" in sys.argv:
        with open(VECTORS_PATH, "w") as f:
            json.dump(vectors, f, indent=2)
            f.write("\n")
        print(f"Froze {VECTORS_PATH}")
    else:
        print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
