#!/usr/bin/env python3
#
# Usage: ./03-analyze-keys.py
#
# This script peforms in-depth analysis of all keys in the unique key index.
# Results are saved in CSV format, with errors being logged to a separate text file.
# The test cases are based on the Browser/CA baseline requirements for TLS certificates.
# Scanning for batch GCD vulnerable keys is not part of this script but must be
# invoked separately through the tool available in ../../tools/RSA-Factorability-Tool
#

import logging
from multiprocessing import Process, Event as NewEvent, Queue
import os
import sys
from threading import Event
from queue import Empty
from time import sleep
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import traceback
from sage.all import Primes, ECM, Integer
from lib.rfc8032 import Edwards25519Point

from tqdm import tqdm

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dsa
from ecpy.curves import Curve, Point, ECPyException
import badkeys
import badkeys.update
import badkeys.checks

from collections import defaultdict

from roca.detect import RocaFingerprinter
from lib.fermat import fermat
from json import dumps
import csv

from config import *

ANALYSIS_RESULTS_OUT = f"{RESULTS_DIR}/03-analysis-results.csv"
ANALYSIS_RESULTS_ERR_OUT = f"{RESULTS_DIR}/03-analysis-errors.txt"


roca_fingerprinter = RocaFingerprinter()

def test_roca_weak(n):
    result = roca_fingerprinter.has_fingerprint_dlog(n)
    if result:
        return True
    else:
        return False

def test_fermat_weak(n):
    return fermat(n)

def ecm_try_factor(n, B1, **kwds):
    # Based on ECM.factor() from SageMath
    ecm = ECM()
    factors = [n]  # factors that need to be factorized futher
    probable_prime_factors = []  # output prime factors
    while factors:
        n = factors.pop()

        # Step 0: Primality test (we are fine with a strong pseudoprime test to save time)
        if n.is_pseudoprime():
            probable_prime_factors.append(n)
            continue

        # Step 1: Use PARI directly for small primes
        if n.ndigits() < 15:
            for p, e in n.factor(algorithm="pari"):
                probable_prime_factors.extend([p] * e)
            continue

        # Step 2: Deal with small factors efficiently
        # Step 2+1/3: Determine if N is a perfect power
        if n.is_perfect_power():
            base, exp = n.perfect_power()
            factors.extend([base] * exp)
            continue

        # Step 2+2/3: Do trial division to remove small prime
        # factors, and maybe some other factorization algorithms
        # that perform well on small ranges. This all depends on
        # the kind of number you are trying to factor (todo)

        # Step 3: Call find_factor until a factorization is found
        try:
            n_factorization = ecm.find_factor(n, B1=B1, **kwds)
            # Add factors 1 < x < n to the list of factors
            factors.extend([x for x in n_factorization if 1 < x < n])
        except ValueError:
            # ECM may throw a ValueError if no factor is found
            pass

    return sorted(probable_prime_factors)

def test_small_factors(n):
    remaining = Integer(n)
    n = Integer(n)
    n_length = n.nbits()
    factors = defaultdict(int)
    # Find all small factors and add them to factors.
    for index, p in enumerate(Primes()):
        while remaining % p == 0:
            factors[p] += 1
            remaining = remaining // p
        # Check the first 10000 primes.
        if index >= 10000:
            break
    # Return early if no small factor has been found.
    if not factors:
        return None, False
    # Check if at least one non-trivial factor is remaining.
    if remaining > 1:
        # Try running ECM to find remaining small factors - if any.
        # ECM.factor() is broken and raises ValueError if the factorization is not complete.
        # Also, some parameters are not passed through to the underlying function.
        # Therefore, use a custom function based on ECM.factor() to factorize the remaining number.
        # B1 = 50000 and c = 300 is a good estimate for factors up to 25 digits.
        # See https://www.rieselprime.de/ziki/Elliptic_curve_method#Choosing_the_best_parameters_for_ECM
        for factor in ecm_try_factor(remaining, B1=50000, c=300):
            factors[factor] += 1
            remaining = remaining // factor
    # Check if factorization is complete.
    product = 1
    for factor, count in factors.items():
        product *= factor**count
    partial = product != n
    # Print out the sorted equation
    msg = "n = "
    for factor, count in sorted(factors.items()):
        if count == 1:
            msg += f"{factor} * "
        else:
            msg += f"{factor}^{count} * "
    if partial:
        msg += f"m, where m has {remaining.nbits()} bits, loss of {n_length - remaining.nbits()} bits"
    else:
        msg = msg[:-3]
    return msg, partial

def analyze_rsa_key(key):
    issues = []
    n = int(key["params"]["n"], 16)
    e = int(key["params"]["e"], 16)

    # CA TLS BR 2.1.2 Section 6.1.5
    # -> NIST SP 800-89 Section 5.3.3 lit. a)
    if key["length"] < 2048:
        issues.append(
            {
                "check": "length_too_short",
                # As of now, the largest publicly known factorization is 829 bits (RSA-250).
                # Key sizes in between 830 and 2048 bits are considered weak but may not
                # be broken yet.
                "fatal": key["length"] < 830,
                "info": f"modulus is of length {key['length']} bits < 2048 bits",
            }
        )
    if key["length"] % 8 != 0:
        issues.append(
            {
                "check": "length_not_multiple_of_8",
                # Not necessarily broken, but may introduce interoperability issues.
                "fatal": False,
                "info": f"modulus is of length {key['length']} bits which is not a multiple of 8",
            }
        )

    # CA TLS BR 2.1.2 Section 6.1.6
    # -> NIST SP 800-89 Section 5.3.3 lit. c)
    if n % 2 == 0:
        issues.append(
            {
                "check": "even_modulus",
                # If the modulus is multiprime, this is not necessarily broken.
                # Otherwise, small_factors will be fatal anyway.
                "fatal": False,
                "info": "modulus is even",
            }
        )
    if e % 2 == 0:
        issues.append(
            {
                "check": "even_exponent",
                # Broken as the exponent is even. In this case e is not invertible modulo phi(n).
                "fatal": True,
                "info": "exponent is even",
            }
        )

    # CA TLS BR 2.1.2 Section 6.1.6
    # -> NIST SP 800-89 Section 5.3.3 lit. b)
    if 2**16 + 1 > e or e > 2**256 - 1:
        issues.append(
            {
                "check": "exponent_out_of_range",
                # Not necessarily broken, just not recommended.
                "fatal": False,
                "info": "exponent is not in the range 2^16 < e < 2^256",
            }
        )

    # CA TLS BR 2.1.2 Section 6.1.6
    # -> NIST SP 800-89 Section 5.3.3 lit. d) (included in below with exponent 1)
    # -> NIST SP 800-89 Section 5.3.3 lit. e)
    if Integer(n).is_prime_power():
        issues.append(
            {
                "check": "prime_power_modulus",
                # It is easy to find the factorization in this case.
                "fatal": True,
                "info": "modulus is a perfect power of a prime",
            }
        )

    # CA TLS BR 2.1.2 Section 6.1.6
    # -> NIST SP 800-89 Section 5.3.3 lit. f)
    small_factors, partial = test_small_factors(n)
    if small_factors is not None:
        issues.append(
            # Broken if we succeeded in factorizing the modulus.
            # Otherwise, the key may not be used due to it being multiprime.
            {"check": "small_factor", "fatal": not partial, "info": small_factors}
        )

    # CA TLS BR 2.1.2 Section 6.1.1.3 Step 3
    # (includes CA TLS BR 2.1.2 Section 6.1.1.3 Step 5.1)
    try:
        key_obj = rsa.RSAPublicNumbers(e, n).public_key()
        compromised = badkeys.checks._checkkey(key_obj, ["blocklist"])
        if "results" in compromised and "blocklist" in compromised["results"]:
            issues.append(
                {
                    "check": "blocklist",
                    # All keys in the blocklist are considered broken.
                    "fatal": True,
                    "info": format_badkeys_blocklist(
                        compromised["results"]["blocklist"]
                    ),
                }
            )
    except Exception:
        pass

    # CA TLS BR 2.1.2 Section 6.1.1.3 Step 4 asks CAs to check
    # that the key has not been revoked previously.

    # CA TLS BR 2.1.2 Section 6.1.1.3 Step 5.2
    roca = test_roca_weak(n)
    if roca:
        issues.append({"check": "roca", "fatal": True, "info": "vulnerable"})

    # CA TLS BR 2.1.2 Section 6.1.1.3 Step 5.3
    fermat = test_fermat_weak(n)
    if fermat:
        issues.append({"check": "fermat", "fatal": True, "info": fermat["debug"]})

    if len(issues) == 0:
        return None
    return {"compromised": any([i["fatal"] for i in issues]), "issues": issues}

def analyze_ed25519_key(key):

    # Trial decoding using RFC8032 decode() method.
    p = Edwards25519Point.stdbase().decode(bytes.fromhex(key["params"]["key"]))
    if p is None:
        return {
            "compromised": False,
            "issues": [
                {
                    "check": "encoding",
                    "fatal": False,
                    "info": "key has an invalid encoding",
                }
            ],
        }

    # Curve25519 has order 8 * q where q = 2^252 + 27742317777372353535851937790883648493
    q = 2**252 + 27742317777372353535851937790883648493
    # All possible orders of elements on Curve25519.
    orders = [1, 2, 4, 8, q, 2 * q, 4 * q, 8 * q]
    for order in orders:
        p_test = p.__mul__(order + 1)
        if p == p_test:
            if order == q:
                break
            return {
                "compromised": False,
                "issues": [
                    {
                        "check": "point_order",
                        "fatal": order < q,
                        "info": f"point order is {order // q} * q + {order % q} (expected q)",
                    }
                ],
            }

    # Check for compromised keys.
    try:
        key_obj = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(key["params"]["key"])
        )
        compromised = badkeys.checks._checkkey(key_obj, ["blocklist"])
        if "results" in compromised and "blocklist" in compromised["results"]:
            return {
                "compromised": True,
                "issues": [
                    {
                        "check": "blocklist",
                        "fatal": True,
                        "info": format_badkeys_blocklist(
                            compromised["results"]["blocklist"]
                        ),
                    }
                ],
            }
    except Exception:
        pass
    return None

def analyze_ecdsa_key(key):
    curve = Curve.get_curve(key["params"]["curve"])
    if curve is None:
        raise ValueError("Unsupported curve: " + key["params"]["curve"])
    try:
        point: Point = curve.decode_point(bytes.fromhex(key["params"]["Q"]))
    except ECPyException:
        return {
            "compromised": False,
            "issues": [
                {
                    "check": "invalid_encoding",
                    "fatal": False,
                    "info": "Q has an invalid encoding",
                }
            ],
        }

    # NIST SP 800-186 Appendix D.1.1.1 Step 1
    # If Q is the point at infinity, output REJECT.
    if point.eq(curve.infinity):
        return {
            "compromised": True,
            "issues": [
                {
                    "check": "point_at_infinity",
                    "fatal": True,
                    "info": "Q is the point at infinity",
                }
            ],
        }

    # NIST SP 800-186 Appendix D.1.1.1 Step 2
    # Let Q = (x, y). Verify that x and y are integers in the interval [0, p−1]. Output REJECT if
    # verification fails.
    if not (0 <= point.x < curve.field):
        return {
            "compromised": False,
            "issues": [
                {
                    "check": "no_field_element",
                    "fatal": False,
                    "info": "x is no element of the underlying field",
                }
            ],
        }
    if not (0 <= point.y < curve.field):
        return {
            "compromised": False,
            "issues": [
                {
                    "check": "no_field_element",
                    "fatal": False,
                    "info": "y is no element of the underlying field",
                }
            ],
        }

    # NIST SP 800-186 Appendix D.1.1.1 Step 3
    # Verify that (x, y) is a point on Wa,b by checking that (x, y) satisfies the defining equation
    # y^2 = x^3 + ax + b, where computations are carried out in GF(p). Output REJECT if
    # verification fails.
    if not curve.is_on_curve(point):
        return {
            "compromised": True,
            "issues": [
                {
                    "check": "not_on_curve",
                    "fatal": True,
                    "info": f"Q is not on curve {curve.name}",
                }
            ],
        }

    # NIST SP 800-186 Appendix D.1.1.2. Step 2
    # Verify that nQ is the point at infinity. Output REJECT if verification fails.
    if not point.mul(curve.order).eq(curve.infinity):
        return {
            "compromised": True,
            "issues": [
                {
                    "check": "wrong_order",
                    "fatal": True,
                    "info": "Q multiplied by the curve order does not equal the point at infinity",
                }
            ],
        }

    # No need to check point order as secp256r1, secp384r1, and secp521r1 have cofactor 1.

    # Check for compromised keys.
    # Convert key to cryptography object which is required by badkeys.
    if key["params"]["curve"] == "secp256r1":
        curve_py = ec.SECP256R1()
    elif key["params"]["curve"] == "secp384r1":
        curve_py = ec.SECP384R1()
    elif key["params"]["curve"] == "secp521r1":
        curve_py = ec.SECP521R1()
    else:
        raise ValueError("Unsupported curve: " + key["params"]["curve"])
    try:
        key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            curve_py, bytes.fromhex(key["params"]["Q"])
        )
        compromised = badkeys.checks._checkkey(key_obj, ["blocklist"])
        if "results" in compromised and "blocklist" in compromised["results"]:
            return {
                "compromised": True,
                "issues": [
                    {
                        "check": "blocklist",
                        "fatal": True,
                        "info": format_badkeys_blocklist(
                            compromised["results"]["blocklist"]
                        ),
                    }
                ],
            }
    except Exception:
        pass
    return None

def analyze_dsa_key(key):
    issues = []

    g = int(key["params"]["g"], 16)
    p = int(key["params"]["p"], 16)
    q = int(key["params"]["q"], 16)
    y = int(key["params"]["y"], 16)

    # NIST SP 800-89 Section 4.1 Step 1
    # SSH only specifies DSA keys in accordance with FIPS 186-2, which specifies the following sizes:
    # - 2^{L - 1} < p < 2^L for 512 <= L <= 1024 and L mod 64 = 0
    # - 2^{159} < q < 2^{160}
    # We consider keys with p < 2048 bits weak. Larger p values, while not being standard compliant,
    # are being used in practice and compatible with OpenSSH. However, q must be 160 bit due to
    # the DSA signature size and the lack of explicit length fields within the signature.
    # An implementation must therefore take the first 160 bit as r and the next 160 bit as s when decoding
    # the signature. The size of p does not affect the size of r and s and can therefore be used.
    if p.bit_length() < 2048:
        issues.append(
            {
                "check": "length_too_short",
                # 795 bits is the largest publicly known dlog (DLOG-240) as of now.
                "fatal": p.bit_length() < 795,
                "info": f"p has {p.bit_length()} bits < 2048 bits",
            }
        )
    # We do not append an issue for q being 160 bit (which is discouraged) as this affects every DSA key in SSH.
    if q.bit_length() != 160:
        issues.append(
            {
                "check": "order_not_160_bit",
                "fatal": q.bit_length() < 160,
                "info": f"q has {q.bit_length()} bits (expected 160 bits)",
            }
        )

    # NIST SP 800-89 Section 4.1 Step 2
    # Check that p is a prime number (use a strong pseudo-primality test only).
    if not Integer(p).is_pseudoprime():
        issues.append(
            {"check": "p_not_prime", "fatal": True, "info": "p is not a prime number"}
        )
    # Check that q is a prime number (use a strong pseudo-primality test only).
    if not Integer(q).is_pseudoprime():
        issues.append(
            {"check": "q_not_prime", "fatal": True, "info": "q is not a prime number"}
        )

    # NIST SP 800-89 Section 4.1 Step 4
    # -> FIPS 186-4 Appendix A.2.2 Step 1
    # Check that 1 < g < p
    if not 1 < g < p:
        issues.append(
            {
                "check": "no_field_element",
                "fatal": False,
                "info": "g is no element in GF(p)",
            }
        )
    # -> FIPS 186-4 Appendix A.2.2 Step 2
    # Check that g has order q mod p.
    if pow(g, q, p) != 1:
        issues.append(
            {
                "check": "wrong_order",
                "fatal": True,
                "info": "g does not have order q mod p",
            }
        )

    # NIST SP 800-89 Section 5.3.1 Step 1
    # Check that 1 < y < p
    if not 1 < y < p:
        issues.append(
            {
                "check": "no_field_element",
                "fatal": False,
                "info": "y is no element in GF(p)",
            }
        )

    # NIST SP 800-89 Section 5.3.1 Step 2
    # Check that y has order q mod p.
    if pow(y, q, p) != 1:
        issues.append(
            {
                "check": "wrong_order",
                "fatal": True,
                "info": "y does not have order q mod p",
            }
        )

    # Check for compromised keys.
    try:
        key_obj = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g)).public_key()
        compromised = badkeys.checks._checkkey(key_obj, ["blocklist"])
        if "results" in compromised and "blocklist" in compromised["results"]:
            issues.append(
                {
                    "check": "blocklist",
                    "fatal": True,
                    "info": format_badkeys_blocklist(
                        compromised["results"]["blocklist"]
                    ),
                }
            )
    except Exception:
        pass
    if len(issues) == 0:
        return None
    return {"compromised": any([i["fatal"] for i in issues]), "issues": issues}

def analyze_key(key_hit):
    key = key_hit["_source"]
    if key["alg"] == "rsa":
        return analyze_rsa_key(key)
    elif key["alg"] == "ed25519":
        return analyze_ed25519_key(key)
    elif key["alg"] == "ecdsa":
        return analyze_ecdsa_key(key)
    elif key["alg"] == "dsa":
        return analyze_dsa_key(key)
    else:
        return None

def process(key_hit):
    try:
        result = analyze_key(key_hit)
        return {"_key": key_hit, "_object": result}
    except Exception as e:
        err = format_exc(key_hit, e)
        return {"_key": key_hit, "_error": err}

def format_badkeys_blocklist(blocklist):
    return f"key has been compromised, reason: {blocklist['subtest']} (badkeys blid: {str(blocklist['blid'])})"

def format_exc(key, e):
    traceback_str = "".join(traceback.format_tb(e.__traceback__))
    return (
        "Error: "
        + str(e)
        + " for key "
        + key["_id"]
        + " in index "
        + key["_index"]
        + ": "
        + repr(key)
        + "\n"
        + traceback_str
    )

def get_total_key_count(algorithm: str | None = None) -> int:
    if algorithm is not None:
        query = {"match": {"alg": algorithm}}
    else:
        query = {"match_all": {}}
    with Elasticsearch(
        ES_URL,
        ca_certs=ES_CA_CERT,
        basic_auth=(ES_USER, ES_PASSWORD),
        request_timeout=ES_REQUEST_TIMEOUT,
    ) as es:
        return es.count(index=INDEX_KEYS_UNIQUE, query=query)["count"]

def key_producer(
    queue: Queue,
    done: Event,
    algorithm: str | None = None,
    batchsize=100000,
    scroll="6h"
):
    query = {"query": {"match_all": {}}}
    if algorithm is not None:
        query = {"query": {"match": {"alg": algorithm}}}
    # Count documents in elasticsearch and update progress bars
    with Elasticsearch(
        ES_URL,
        ca_certs=ES_CA_CERT,
        basic_auth=(ES_USER, ES_PASSWORD),
        request_timeout=ES_REQUEST_TIMEOUT,
    ) as es:
        # Adjust result window on source index to allow for larger batch sizes.
        es.indices.put_settings(
            index=INDEX_KEYS_UNIQUE,
            body={"index.max_result_window": max(batchsize, 10000)},
        )
        for hit in scan(
            es,
            index=INDEX_KEYS_UNIQUE,
            scroll=scroll,
            query=query,
            size=batchsize,
            request_timeout=ES_REQUEST_TIMEOUT,
        ):
            queue.put(hit)
    done.set()

def key_consumer(queue: Queue, result_queue: Queue, done: Event):
    while not done.is_set() or not queue.empty():
        try:
            key_hit = queue.get(block=False)
            result = process(key_hit)
            result_queue.put(result)
        except Empty as _:
            sleep(0.1)
            pass


if __name__ == "__main__":
    logging.getLogger("elastic_transport.transport").setLevel(logging.ERROR)
    badkeys.update.update_bl(True, True)
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    if os.path.exists(ANALYSIS_RESULTS_OUT):
        tqdm.write("Results file already exists. Exiting.")
        sys.exit(1)
    queue = Queue()
    result_queue = Queue()
    done = NewEvent()
    # Start producer and consumers
    producer = Process(target=key_producer, args=(queue, done, None, BATCH_SIZE))
    consumers = [
        Process(target=key_consumer, args=(queue, result_queue, done))
        for _ in range(PARALLEL_WORKERS)
    ]
    producer.start()
    for consumer in consumers:
        consumer.start()
    # Process results
    with open(ANALYSIS_RESULTS_OUT, "w") as out_res, open(
        ANALYSIS_RESULTS_ERR_OUT, "w"
    ) as out_err:
        csv_writer = csv.writer(out_res)
        for _ in tqdm(
            range(get_total_key_count()), desc="Keys analyzed", unit="keys"
        ):
            result = result_queue.get()
            if "_error" in result:
                tqdm.write("Error: " + result["_error"])
                out_err.write(result["_error"] + "\n")
            else:
                if result["_object"] is not None:
                    if result["_object"]["compromised"]:
                        tqdm.write(
                            "Result: "
                            + result["_key"]["_source"]["fpr"]
                            + " "
                            + repr(result["_object"])
                        )
                    csv_writer.writerow(
                        [
                            result["_key"]["_index"],
                            result["_key"]["_id"],
                            result["_key"]["_source"]["alg"],
                            result["_key"]["_source"]["fpr"],
                            dumps(result["_key"]["_source"]["source"]),
                            dumps(result["_object"]),
                        ]
                    )
