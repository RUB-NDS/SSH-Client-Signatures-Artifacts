#!/usr/bin/env python3
#
# Usage: ./07-generate-test-keys.py
#
# This script generates test keys for various algorithms and key sizes,
# that can be used to test upload restrictions on Git-based hosting services.
# The resulting file will contain one public key entry per line, similar to the
# authorized_keys file format of OpenSSH. Most keys are generated on the fly.
#

import base64
import math
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec, dsa
from ecpy.curves import Curve, ECPyException
from sage.all import Integer, IntegerModRing, random_prime, next_prime
from sage.rings.finite_rings.integer_mod import IntegerMod

from lib.rfc8032 import Edwards25519Point
from config import *

def _no_verify(public_exponent: int, key_size: int):
    pass
rsa._verify_rsa_parameters = _no_verify

def encode_string(s: str | bytes) -> bytes:
    if isinstance(s, str):
        s = s.encode("ascii")
    return len(s).to_bytes(4, "big") + s


def encode_mpint(mpint: int) -> bytes:
    if mpint == 0:
        return b"\x00\x00\x00\x01\x00"
    encoded = mpint.to_bytes(math.ceil(mpint.bit_length() / 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return len(encoded).to_bytes(4, "big") + encoded


def serialize_rsa_key(e: int, n: int) -> bytes:
    return encode_string("ssh-rsa") + encode_mpint(e) + encode_mpint(n)


def serialize_ed25519_key(Q: bytes) -> bytes:
    return encode_string("ssh-ed25519") + encode_string(Q)


def serialize_ecdsa_key(curve: str, Q: bytes) -> bytes:
    return (
        encode_string("ecdsa-sha2-" + curve) + encode_string(curve) + encode_string(Q)
    )


def serialize_dsa_key(p: int, q: int, g: int, y: int) -> bytes:
    return (
        encode_string("ssh-dss")
        + encode_mpint(p)
        + encode_mpint(q)
        + encode_mpint(g)
        + encode_mpint(y)
    )


def generate_rsa_primes(key_size: int) -> tuple[int, int]:
    sk = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return sk.private_numbers().p, sk.private_numbers().q


def generate_rsa_public_key(key_size: int) -> tuple[int, int]:
    sk = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pk = sk.public_key()
    return pk.public_numbers().e, pk.public_numbers().n


def generate_rsa_test_keys() -> list[(str, str, bytes)]:
    keys = []

    # valid
    e, n = generate_rsa_public_key(2048)
    keys.append(("ssh-rsa", "rsa-valid", serialize_rsa_key(e, n)))

    # length_too_short
    e, n = generate_rsa_public_key(1024)
    keys.append(("ssh-rsa", "rsa-1024", serialize_rsa_key(e, n)))
    e, n = generate_rsa_public_key(1023)
    keys.append(("ssh-rsa", "rsa-1023", serialize_rsa_key(e, n)))
    e, n = generate_rsa_public_key(1022)
    keys.append(("ssh-rsa", "rsa-1022", serialize_rsa_key(e, n)))
    e, n = generate_rsa_public_key(512)
    keys.append(("ssh-rsa", "rsa-512", serialize_rsa_key(e, n)))

    # length_not_multiple_of_8
    e, n = generate_rsa_public_key(2047)
    keys.append(("ssh-rsa", "rsa-length-not-multiple-of-8", serialize_rsa_key(e, n)))

    # even_modulus
    e, n = generate_rsa_public_key(2048)
    n ^= 1
    keys.append(("ssh-rsa", "rsa-even-modulus", serialize_rsa_key(e, n)))

    # even_exponent
    e, n = generate_rsa_public_key(2048)
    e ^= 1
    keys.append(("ssh-rsa", "rsa-even-exponent", serialize_rsa_key(e, n)))

    # exponent_out_of_range
    e, n = generate_rsa_public_key(2048)
    keys.append(("ssh-rsa", "rsa-exponent-out-of-range", serialize_rsa_key(37, n)))

    # prime_power_modulus
    n = Integer(0)
    while n.nbits() != 2048:
        p = random_prime(2**1024 - 1, False, 2**1023)
        n = p**2
    e = 65537
    n = int(n)
    keys.append(("ssh-rsa", "rsa-prime-power-modulus", serialize_rsa_key(e, n)))

    # small_factor
    n = Integer(0)
    while n.nbits() != 2048:
        p = Integer(3)
        q = random_prime(2**2046 - 1, False, 2**2045)
        n = p * q
    e = 65537
    n = int(n)
    keys.append(("ssh-rsa", "rsa-small-factor", serialize_rsa_key(e, n)))

    # blocklist (debian weak key)
    # source: badkeys.info
    e = 65537
    n = int(
        "c096530c4c4a343fc388ff8b6e14c88b617485966dd0f757f3decb2f03dfdfe6f518e0948f5387059bd5aa124f26d38f139dd6ebc234360561689758e9b14e03f714508167374cbf64e24e26c3cd95ed5a5d04e3c404be157bb8090e9ada9cdc53ef7e806c1e77b5f10242150a24e9adf991088daf20a75beb54bc91fe43dd8755447fd3abdefb9f1c987a8b0419824504e213f8dd26a9c6b7ed2f2103d8422720f7a7400ce34743e4ce40440c69013efea2a39790fcdfccbb424da1d824adfe58071ed76d41af836e4093ea60f5719e250fa214f8631153a81eefc17d82e3f819da57691ed9602550074fdea73ac9e5cfe10f6b91adc31b402c3e370b03a559",
        16,
    )
    keys.append(("ssh-rsa", "rsa-debian-weak-key", serialize_rsa_key(e, n)))

    # blocklist (keypair vuln)
    # source: badkeys.info
    e = 65537
    n = int(
        "8b78954460f76d3ee9ea0221d83e7dd12649b666c9fad89e5190e204f40bae798c3c397e04305eba2c7b44779c95f6ee31e7de4a7aad5d183cb605dc2db5a03947d96fec0e0e0af4b1e91dec8ca8e37f210a904364508f6edf4640681c68f002dbdb1d6d76032824dbde7a8a39501933b2d3db472c5a8dade90afb2b9d1bb033b75dd119e1c4a2583221bd2b19397b1afa51ff84133f208800dc6845b730c0cff3f38f9a406c8f4364850fac30e14fce17d31b5582d1370e629ec993cb275fed1283b04e2ba3c4dbcdc3ada291ec2189a962a7e030c79564d2ae8ad5b95c4149d8dba18cf232b0bb19856ddd3fc6bf81a13cd8f2ff859a54bcc5959c3dac9fbf",
        16,
    )
    keys.append(("ssh-rsa", "rsa-keypair-vuln", serialize_rsa_key(e, n)))

    # roca
    # source: badkeys.info
    e = 65537
    n = int(
        "9132ad211fcc0dfb4dae48326ac864c227e4b394b09bd1c4930e197028a3c907694d2b489e4f69754aeae338c6ead939c57f406985cbbb8edf9a2055cc2946bc05d365ba67e896c6d4811152cfa2d290514f90b352eeef27feb72fbd8dcd5bc915a4f4494139cc1ca10a3244fa97e53275f57b5529b4e767379007798e112a4ba056c7b75cedb132cdf21f7bd3c9976d9da38815153477a13b3ebb2046d100a851dc00698f530d19396f00fbef2c4bf1659ebc4c7fd9556b5ffc93f03ca2d3dfacd222a5f028ab430a27ea31136c0c2f50c3c481931a635a37780f00d2727ae71aee9b40f8d1aae68535c77a56317812beb5525d4a28364f31224acac52cf72d",
        16,
    )
    keys.append(("ssh-rsa", "rsa-roca", serialize_rsa_key(e, n)))

    # fermat
    n = Integer(0)
    while not n.nbits() == 2048:
        p = random_prime(2**1024 - 1, False, 2**1023)
        q = next_prime(p)
        n = p * q
    e = 65537
    n = int(n)
    keys.append(("ssh-rsa", "rsa-fermat", serialize_rsa_key(e, n)))

    return keys


def generate_ed25519_test_keys() -> list[(str, str, bytes)]:
    keys = []

    # valid
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    Q = pk.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    keys.append(("ssh-ed25519", "ed25519-valid", serialize_ed25519_key(Q)))

    # encoding
    invalid_enc = False
    while not invalid_enc:
        Q = os.urandom(32)
        p = Edwards25519Point.stdbase().decode(Q)
        if p is None:
            invalid_enc = True
    keys.append(("ssh-ed25519", "ed25519-encoding", serialize_ed25519_key(Q)))

    # point_order
    # source: https://github.com/jedisct1/libsodium/blob/e985fe204c81fa4da3855226449dbb686b8eaffd/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1006
    # order 1, 2, 4, 8 from known points
    Q = b"\x01" + b"\x00" * 31
    p = Edwards25519Point.stdbase().decode(Q)
    assert p == p * 2
    keys.append(("ssh-ed25519", "ed25519-point-order-1", serialize_ed25519_key(Q)))
    Q = b"\xec" + b"\xff" * 30 + b"\x7f"
    p = Edwards25519Point.stdbase().decode(Q)
    assert p == p * 3
    keys.append(("ssh-ed25519", "ed25519-point-order-2", serialize_ed25519_key(Q)))
    Q = b"\x00" * 32
    p = Edwards25519Point.stdbase().decode(Q)
    assert p == p * 5
    keys.append(("ssh-ed25519", "ed25519-point-order-4", serialize_ed25519_key(Q)))
    Q = b"\x26\xe8\x95\x8f\xc2\xb2\x27\xb0\x45\xc3\xf4\x89\xf2\xef\x98\xf0\xd5\xdf\xac\x05\xd3\xc6\x33\x39\xb1\x38\x02\x88\x6d\x53\xfc\x05"
    p = Edwards25519Point.stdbase().decode(Q)
    assert p == p * 9
    keys.append(("ssh-ed25519", "ed25519-point-order-8", serialize_ed25519_key(Q)))
    # orders 2q, 4q, 8q from random points
    q = 2**252 + 27742317777372353535851937790883648493
    notFound = [True, True, True]
    highOrderPoints = [b"", b"", b""]
    while any(notFound):
        try:
            Q = os.urandom(32)
            p = Edwards25519Point.stdbase().decode(Q)
            # Ensure that ord(p) > q
            if p == p * 2 or p == p * 3 or p == p * 5 or p == p * 9 or p == p * (q + 1):
                continue
            for i in range(3):
                if p == p * (2 ** (i + 1) * q + 1) and notFound[i]:
                    highOrderPoints[i] = Q
                    notFound[i] = False
        except:
            pass
    for i in range(3):
        keys.append(
            (
                "ssh-ed25519",
                "ed25519-point-order-" + str(2 ** (i + 1)) + "q",
                serialize_ed25519_key(highOrderPoints[i]),
            )
        )

    return keys


def generate_ecdsa_test_keys() -> list[(str, str, bytes)]:
    keys = []

    # valid
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    Q = pk.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    keys.append(
        ("ecdsa-sha2-nistp256", "ecdsa-valid", serialize_ecdsa_key("nistp256", Q))
    )

    # encoding
    curve = Curve.get_curve("secp256r1")
    invalid_enc = False
    while not invalid_enc:
        Q = os.urandom(65)
        try:
            pk = curve.decode_point(Q)
        except ECPyException:
            invalid_enc = True
    keys.append(
        ("ecdsa-sha2-nistp256", "ecdsa-encoding", serialize_ecdsa_key("nistp256", Q))
    )

    #  point_at_infinity
    Q = b"\x00"
    keys.append(
        (
            "ecdsa-sha2-nistp256",
            "ecdsa-point-at-infinity",
            serialize_ecdsa_key("nistp256", Q),
        )
    )

    # no_field_element
    p = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    a = int("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
    b = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    small_x_found = False
    while not small_x_found:
        try:
            x = int.from_bytes(os.urandom(27), "big")
            y = curve.y_recover(x, 0)
            assert y**2 % p == (x**3 + a * x + b) % p
            small_x_found = True
        except:
            pass
    Q = b"\x04" + (x + p).to_bytes(32, "big") + y.to_bytes(32, "big")
    keys.append(
        (
            "ecdsa-sha2-nistp256",
            "ecdsa-no-field-element-x",
            serialize_ecdsa_key("nistp256", Q),
        )
    )
    small_y_found = False
    # Find a point (x, y) on the curve such that
    # y^2 = x^3 + ax + b and y small, i. e. (y + p) < 2^256
    # To do so, we generate a random small y and solve the resulting cubic equation
    R = IntegerModRing(Integer(p))
    twoInt = IntegerMod(R, Integer(2))
    fourInt = IntegerMod(R, Integer(4))
    twentySevenInt = IntegerMod(R, Integer(27))
    aInt = IntegerMod(R, Integer(a))
    while not small_y_found:
        try:
            # y^2 = x^3 + ax + b <=> x^3 + ax + b - y^2 = 0 <=> x^3 + ax + c = 0
            y = int.from_bytes(os.urandom(27), "big")
            cMod = IntegerMod(R, Integer(b - y**2))
            # Cardano's method for depressed cubic equations
            # Adapted to residue class ring modulo p
            # u = cbrt(-c*2^{-1} + sqrt(c^2*4^{-1} + a^3*27^{-1})) mod p
            u = (-cMod * twoInt**-1 +
                    (cMod**2 * fourInt**-1 + aInt**3 * twentySevenInt**-1).sqrt(extend=False)
                ).nth_root(3, extend=False)
            # v = cbrt(-c*2^{-1} - sqrt(c^2*4^{-1} + a^3*27^{-1})) mod p
            v = (-cMod * twoInt**-1 -
                    (cMod**2 * fourInt**-1 + aInt**3 * twentySevenInt**-1).sqrt(extend=False)
                ).nth_root(3, extend=False)
            # x = u + v is a solution to the curve's cubic equation
            x = int(u + v)
            assert y**2 % p == (x**3 + a * x + b) % p
            small_y_found = True
        except:
            pass
    Q = b"\x04" + x.to_bytes(32, "big") + (y + p).to_bytes(32, "big")
    keys.append(
        (
            "ecdsa-sha2-nistp256",
            "ecdsa-no-field-element-y",
            serialize_ecdsa_key("nistp256", Q),
        )
    )

    # not_on_curve
    on_curve = True
    while on_curve:
        try:
            x = int.from_bytes(os.urandom(32), "big") % p
            y = int.from_bytes(os.urandom(32), "big") % p
            assert y**2 % p != (x**3 + a * x + b) % p
            on_curve = False
        except:
            pass
    Q = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    keys.append(
        (
            "ecdsa-sha2-nistp256",
            "ecdsa-not-on-curve",
            serialize_ecdsa_key("nistp256", Q),
        )
    )

    # wrong_order not possible on nistp256 because cofactor is 1

    # blocklist (debian weak key)
    # source: badkeys.info
    Q = b"\x04\xad\x4a\xd9\xbc\x1e\x2d\x03\xce\x78\x6e\x58\xb3\x63\xa6\x7a\x04\x4b\xf0\x22\xeb\xc2\x93\x96\x67\xf5\x2f\xf5\x96\xec\xaa\xe3\x33\xe4\xca\x6d\x6e\x04\x76\x07\xd7\xa9\x83\xec\x92\x12\xe3\x95\x09\x50\xdd\xc8\x4e\x68\x86\x49\x54\x4e\xbe\x06\x8c\x45\xe9\xef\xdd"
    keys.append(
        (
            "ecdsa-sha2-nistp256",
            "ecdsa-debian-weak-key",
            serialize_ecdsa_key("nistp256", Q),
        )
    )

    return keys


def generate_dsa_test_keys() -> list[(str, str, bytes)]:
    keys = []

    # valid ssh-dss key although length_too_short
    sk = dsa.generate_private_key(key_size=1024)
    pk = sk.public_key()
    p = pk.parameters().parameter_numbers().p
    q = pk.parameters().parameter_numbers().q
    g = pk.parameters().parameter_numbers().g
    y = pk.public_numbers().y
    keys.append(("ssh-dss", "dsa-valid", serialize_dsa_key(p, q, g, y)))

    # p_2048_bit_q_160_bit
    # invalid per RFC 4253 and FIPS 186-3 but accepted by some SSH implementations
    p = int(
        "8f0ca67c4e3dec34fce882740972b4db34050b470f5845d73c0490369ef3bbeb1e55209a33bb986cd0ee25c0d1f1fd449e34cd372101e42a3c9e7919ceeb3a46ecbdddf5cf5bf0bde506d9119ed91e504604a144dfce77f34cc74915395ec81da56002be4950ec7abb0327f2bea843279e99da68eb33814b09018eb553e7b9165db1c1b3584bc166df09d7b70d39275356e1174e0671409209758d9723aa100b6bda01c36dcade6a0b3916ed72d70a978c0f36bee96ee451d5407d1cec22b189720784cf1289600df2de090dcf4bddfdc1285e7f4bee90906336ab8f74e00ed2c79302684717dd0977b5b110f72dd0d5fa4264818a3afe59b406ae5e1f6cf869",
        16,
    )
    q = int("b976d17db22d3fcbd308d96fd162dea3103d9055", 16)
    g = int(
        "0100da7786f319713960ca71f690400cd688936ae7566cbc891155b37222ac211871d0d14b57bfca3c9e77964778597e7a67e888325b0cc942513f8a1e39dc41290889dea69ba79f3b1bdd16f23495f5b126f3e25ad0d73bf5658776236f74931a00fa5e601e6c6cba3011138de686bb516f0a3df5b8c79b63367fc361bb0113652e560119102882ad9f2b52d8afde612f179b777c93369126c80b8e535ac94e87b90890913b1da2afede175759eae4cc7cfb3d85fd762eabce5b865940d097080c50b3b0bdd86b7f73d2490c3675357e64c72bc72464bb9c64dc557ad93066edda937534eeda8b690397257f4b4f3409b559cf497919cbe91395e0b39f4c9e2",
        16,
    )
    y = int(
        "5668e15559d2144affa7a5768f2fb0005dd437ed2e9da3362643e406411672b0daa6c26b17cbe499829139e9dda18378875436593dbe1c97a5c6f63b8090c32cebb0156a8ae837f488d9b80f32f89f500db209c635068c58fada243d5ff9119668a28ea4295525731eb5968182064e7ecee3597d0f8d7ea428204c9ac5f046ec77cb7408a5b0460b72096bff97bd32989f00a30beac00b9733aadf32cb9e95a4da48ec3269b91b7d457dfd349d69cb3ff441f891e963346d031187957ee4b287df2ea7797fab8ce62ea628c242419bdabc2d7796a6ce2189628f8e513cf187ef8507039de7a7ccd7f9b1680a3c73c0c7e927dd04e9d7e72811dbf0fc181b5de3",
        16,
    )
    keys.append(("ssh-dss", "dsa-2048bit-p", serialize_dsa_key(p, q, g, y)))

    # order_not_160_bit
    # Specifying a p size of 2048 bit will yield a q size of 256 bit
    sk = dsa.generate_private_key(key_size=2048)
    pk = sk.public_key()
    p = pk.parameters().parameter_numbers().p
    q = pk.parameters().parameter_numbers().q
    g = pk.parameters().parameter_numbers().g
    y = pk.public_numbers().y
    keys.append(("ssh-dss", "dsa-order-not-160-bit", serialize_dsa_key(p, q, g, y)))

    # p_not_prime
    p = Integer(0)
    while p.is_pseudoprime() or p.nbits() != 1024:
        q = random_prime(2**160 - 1, False, 2**159)
        p = (q * 2 << (1024 - 160 - 1)) + 1
    p = int(p)
    q = int(q)
    # We don't care about the generator g and the public key y
    g = int.from_bytes(os.urandom(128), "big") % p
    y = int.from_bytes(os.urandom(128), "big") % p
    keys.append(("ssh-dss", "dsa-p-not-prime", serialize_dsa_key(p, q, g, y)))

    # q_not_prime
    p = Integer(0)
    while not p.is_pseudoprime() or p.nbits() != 1024:
        q = Integer(int.from_bytes(os.urandom(20), "big"))
        if q.nbits() != 160:
            continue
        p = (q * 2 << (1024 - 160 - 1)) + 1
    p = int(p)
    q = int(q)
    # We don't care about the generator g and the public key y
    g = int.from_bytes(os.urandom(128), "big") % p
    y = int.from_bytes(os.urandom(128), "big") % p
    keys.append(("ssh-dss", "dsa-q-not-prime", serialize_dsa_key(p, q, g, y)))

    # no_field_element
    sk = dsa.generate_private_key(key_size=1024)
    pk = sk.public_key()
    p = pk.parameters().parameter_numbers().p
    q = pk.parameters().parameter_numbers().q
    g = pk.parameters().parameter_numbers().g
    y = pk.public_numbers().y
    keys.append(
        ("ssh-dss", "dsa-no-field-element-g", serialize_dsa_key(p, q, g + p, y))
    )
    keys.append(
        ("ssh-dss", "dsa-no-field-element-y", serialize_dsa_key(p, q, g, y + p))
    )

    # wrong_order
    sk = dsa.generate_private_key(key_size=1024)
    pk = sk.public_key()
    p = pk.parameters().parameter_numbers().p
    q = pk.parameters().parameter_numbers().q
    g = pk.parameters().parameter_numbers().g
    y = pk.public_numbers().y
    # Use p - 1 as generator and public key to get a wrong order (p - 1 has order 2)
    keys.append(("ssh-dss", "dsa-wrong-order-g", serialize_dsa_key(p, q, p - 1, y)))
    keys.append(("ssh-dss", "dsa-wrong-order-y", serialize_dsa_key(p, q, g, p - 1)))

    # blocklist (debian weak key)
    # source: badkeys.info
    p = int(
        "00930ea3cfd441cb5c466eebf41d9f8842d28468b73f9e0bdb81184dc6aa1fdc3b6b622ff052a57fc1afdea83e5f926c8f0bbad4d2457193fdd8b0d23c1ffa365c0d35f727969a486dd2ac895f42371e5b5e1643c31c557d3edc84c03502abcf6ae637cf37ef9ac978d10ecc5af0e7a44add16a26c6f6760be5e33a8a28527528d",
        16,
    )
    q = int("00fe645974f53dddf58d4c286113d28fa490d7939d", 16)
    g = int(
        "7f61e8834b39a88a519a22245eff6fde969e3042624ea6f34afd3c7db22b2d690d35f2eb8786df082c41f26a783c3ed6ea6edb61b35d0be2b6b41e225f1d02cbed4fd202606323dfdea43075744dde9174c0283aa7ddf728f831c84b8f12c8b7edb2ad3d6847584f0ea9b157bbf297276cd7c4ae4e18f179a27df96ab6451720",
        16,
    )
    y = int(
        "1c79c4e7d7750fccf86da0c8e706594d41333b982ee7c030a097d65ebe3a1f85912dd3fd0da9376036b403faa2fd82c30e03a9e9fea90376f7b987e9aba91208572b1d57bd7189be31d8b27bb2f582e4128514918b5b1b698a9037131fd3040409bd3a6e05ccd258dcae717bae1df0a3e3299895345ac9be64770648b5c0dabd",
        16,
    )
    keys.append(("ssh-dss", "dsa-debian-weak-key", serialize_dsa_key(p, q, g, y)))

    return keys


if __name__ == "__main__":
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    with open(f"{RESULTS_DIR}/07-test-keys.txt", "w") as f:
        test_keys = (
            generate_dsa_test_keys()
            + generate_rsa_test_keys()
            + generate_ecdsa_test_keys()
            + generate_ed25519_test_keys()
        )
        for key in test_keys:
            encoded_key = base64.b64encode(key[2]).decode()
            f.write(f"{key[0]} {encoded_key} {key[1]}\n")
