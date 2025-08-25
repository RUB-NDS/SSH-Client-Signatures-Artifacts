import ipaddress
import logging
from pathlib import Path
from time import time

import gmpy2
from gmpy2 import *
from primefac import primefac
from pymongo import *
from tqdm import tqdm

from tool.data.Database import Database
from tool.rsa.KeyTreeNode import KeyTreeNode
import multiprocessing as mp

logger = logging.getLogger()

def multiply_neighbours(nums, mp_pool, depth=1):
    """
    Multiplys array neighbours together using multiprocessing
    Given A[1...4] will result in B[1..2] with B[1] = A[1]*A[2] and B[2] = A[3]*A[4]

    :param nums: array of numbers to use for multiplication
    :param mp_pool: multiprocessing process pool
    :param depth: number of neightbour multiplication iteration
    :return: the multiplication result
    """
    new_nums = []
    for x in range(0, len(nums) - 1, 2):
        new_nums.append(mp_pool.apply_async(mul, args=(nums[x], nums[x + 1])))
    new_nums = [x.get() for x in new_nums]
    if len(nums) % 2 == 1:
        new_nums.append(nums[-1])
    if depth > 1:
        new_nums = multiply_neighbours(new_nums, mp_pool, depth=depth - 1)
    return new_nums


def batch_modulo(nums, modulus, mp_pool):
    """
    Apply modulo operation to array with multiprocessing

    :param nums: Number Array
    :param modulus: Modulus to use
    :param mp_pool: Multiprocessing pool
    :return: Resulting Number Array
    """
    results = [mp_pool.apply_async(f_mod, args=(x, modulus)) for x in nums]
    return [x.get() for x in results]


def keytree_factorability(N, moduli, mp_pool):
    n_squared = N * N
    while len(moduli) > 1:
        moduli = batch_modulo(moduli, n_squared, mp_pool)
        moduli = multiply_neighbours(moduli, mp_pool, depth=4)
    return moduli[0]


def analyze_factorability(config):
    """
    Runs the factorable key analysis

    :param config: Configuration for databank access
    :return:
    """

    num_processes = mp.cpu_count()
    start = time()
    db = Database(config)
    root_moduli = []
    root_nodes = []
    keytree_collection_list = db.database.list_collection_names(filter={"name": {"$regex": r"^keytree"}})
    for coll_name in keytree_collection_list:
        coll = db.database[coll_name]
        root_node_db = coll.find_one(sort=[("h", DESCENDING)])
        N = from_binary(root_node_db.get("N"))
        root_node = KeyTreeNode(root_node_db.get("h"), N, coll, root_node_db.get("_id"))
        root_nodes.append(root_node)
        root_moduli.append(N)
    pool = mp.Pool(processes=num_processes)
    logger.info("Starting pool...")
    root_moduli = multiply_neighbours(root_moduli, pool, depth=8)
    for i in range(len(root_nodes)):
        logger.info(f"Analysing keytree {i}[{root_nodes[i].collection}]")
        root_remainder = keytree_factorability(root_nodes[i].N, root_moduli, pool)
        logger.info("Starting analysis")
        dfs(db, root_nodes[i], root_remainder, pool)
    pool.close()
    pool.join()
    logger.info("Pool processing done")
    db.finish()
    logger.info(f"Done, took{time() - start}")


def final_gcd(N, node_N, db_id):
    """
    Final step for GCD calculation
    """
    remainder = gmpy2.divexact(N, node_N)
    g = gmpy2.gcd(mpz(remainder), node_N)
    if g != 1:
        logger.info(f"{db_id} showed GCD of {g}")


def _mod(N, child_n):
    modulus = child_n * child_n
    return f_mod(N, modulus)


def dfs(db, keytreenode, N, mp_pool):
    """
    Recursive remainder tree calculation
    """
    if keytreenode.height == 0:
        mp_pool.apply_async(final_gcd, args=(N, keytreenode.N, keytreenode.db_id))
        return

    children = db.get_children(keytreenode)
    lc_N = children[0].N
    rc_N = children[1].N

    left_remainder_async = mp_pool.apply_async(_mod, args=(N, lc_N))
    right_remainder_async = mp_pool.apply_async(_mod, args=(N, rc_N))

    dfs(db, children[0], left_remainder_async.get(), mp_pool)
    dfs(db, children[1], right_remainder_async.get(), mp_pool)


def reuse_key_in_cert_analysis(config, results_dir):
    db_client = MongoClient(config["mongodb"]["host"] + ":" + config["mongodb"]["port"])
    database = db_client[config["mongodb"]["db_name"]]

    result = database.certs.aggregate([
        {
            "$group": {
                "_id": "$key",
                "count": {"$sum": 1},
                "docs": {"$push": "$_id"}
            }
        },
        {
            "$match": {
                "count": {"$gt": 1}
            }
        },
        {
            "$sort": {
                "count": DESCENDING
            }
        }
    ], allowDiskUse=True
    )

    Path(results_dir).mkdir(parents=True, exist_ok=True)

    total_repetitions = 0
    total_keys = 0

    for entry in result:
        total_repetitions += entry.get("count")
        total_keys += 1
        if entry.get("count") < 50: continue
        print("Key", entry.get("_id"), "is duplicate", entry.get("count"), "times")
        certs = entry.get("docs")
        with open(results_dir + "/" + str(entry.get("_id")) + ".csv", "w", encoding="utf-8") as outfile:
            outfile.write("Key is duplicate " + str(entry.get("count")) + " times in certificates with the following "
                                                                          "additional certificate information\n")
            for cert in certs:
                try:
                    certificate = database.certs.find_one({"_id": cert})
                    add_info = certificate.get("add_info")
                    add_info_csv_str = ""
                    for y in add_info:
                        add_info_csv_str += str(add_info.get(y)) + ";"
                    outfile.write(add_info_csv_str + "\n")
                    occurrences = database.occurrences.find({"cert": cert})
                    for occ in occurrences:
                        outfile.write("\tOccurrence: " + str(ipaddress.IPv4Address(occ.get("ip"))) + ":" + str(
                            occ.get("port")) + "\n")
                except Exception as e:
                    print(e)
            outfile.flush()

    db_client.close()
    print("Successfully written results. Total keys:", total_keys, "; Total repetitions: ", total_repetitions)


def reuse_cert_analysis(config, results_dir):
    db_client = MongoClient(config["mongodb"]["host"] + ":" + config["mongodb"]["port"])
    database = db_client[config["mongodb"]["db_name"]]

    result = database.occurrences.aggregate([
        {
            '$group': {
                '_id': '$cert',
                'count': {
                    '$sum': 1
                }
            }
        }, {
            '$match': {
                'count': {
                    '$gt': 50
                }
            }
        }, {
            '$lookup': {
                'from': 'occurrences',
                'localField': '_id',
                'foreignField': 'cert',
                'as': 'docs'
            }
        }, {
            '$addFields': {
                'docs': {
                    '$reduce': {
                        'input': '$docs',
                        'initialValue': [],
                        'in': {
                            '$cond': [
                                {
                                    '$in': [
                                        '$$this.ip', '$$value.ip'
                                    ]
                                }, '$$value', {
                                    '$concatArrays': [
                                        '$$value', [
                                            '$$this'
                                        ]
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        }, {
            '$addFields': {
                'count': {
                    '$size': '$docs'
                }
            }
        }, {
            '$match': {
                'count': {
                    '$gt': 50
                }
            }
        }, {
            '$lookup': {
                'from': 'certs',
                'localField': '_id',
                'foreignField': '_id',
                'as': 'cert'
            }
        }, {
            '$unwind': {
                'path': '$cert'
            }
        }, {
            '$sort': {
                'count': -1
            }
        }
    ], allowDiskUse=True)
    for x in result:
        add_info = x.get("cert").get("add_info")
        add_info_csv_str = ""
        for y in add_info:
            add_info_csv_str += str(add_info.get(y)) + ";"
        print(x.get("_id"), "appeared", x.get("count"), "times, add_info:", add_info_csv_str)
        print("\t", end="")
        for y in x.get("docs"):
            print(str(ipaddress.IPv4Address(y.get("ip")) + ":" + str(y.get("port"))))

def node_recursive_primefactor_analysis(db, node, prime):
    factor = gcd(prime, node.N)
    if factor > 1:
        if node.height == 0:
            primefactors_of_factor = list(int(x) for x in primefac(factor))
            logger.info(f"{node.db_id} showed primefactors {primefactors_of_factor}")
        else:
            children = db.get_children(node)
            lc = children[0]
            rc = children[1]
            node_recursive_primefactor_analysis(db, lc, prime)
            node_recursive_primefactor_analysis(db, rc, prime)



def primefactor_analysis(config, primesfile):
    start = time()
    primes = []
    with open(primesfile, "r") as f:
        for line in f.readlines():
            primes.append(mpz(line.split(",")[-1]))
    primeproduct = mpz(1)
    for prime in primes:
        primeproduct *= prime

    db = Database(config)
    keytree_collection_list = db.database.list_collection_names(filter={"name": {"$regex": r"^keytree"}})

    progress = tqdm(total=len(keytree_collection_list))
    for coll_name in keytree_collection_list:
        coll = db.database[coll_name]
        root_node_db = coll.find_one(sort=[("h", DESCENDING)])
        N = from_binary(root_node_db.get("N"))
        root_node = KeyTreeNode(root_node_db.get("h"), N, coll, root_node_db.get("_id"))

        #for prime in primes:
        #    node_recursive_primefactor_analysis(db, root_node, prime)
        #    progress.update()
        node_recursive_primefactor_analysis(db, root_node, primeproduct)
        progress.update()


    db.finish()
    logger.info(f"Done, took {time() - start}")