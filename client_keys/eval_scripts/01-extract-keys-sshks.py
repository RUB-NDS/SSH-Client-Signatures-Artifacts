#!/usr/bin/env python3
import math
import traceback
import os
import base64
import hashlib

from elasticsearch import Elasticsearch
from mpire import WorkerPool
from mpire.utils import make_single_arguments
from tqdm import tqdm

from myssh import load_ssh_public_key
from elasticsearch.helpers import parallel_bulk, scan

from myssh import _SSHFormatDSA


def _no_validate(self, x):
    pass


_SSHFormatDSA._validate = _no_validate

ES_URL = [
    "https://192.168.66.3:9200",
    "https://192.168.66.5:9200",
    "https://192.168.66.125:9200",
]
ES_CA_CERT = "ca.crt"
ES_USER = "elastic"
ES_PASSWORD = "<<< password >>>"

INDEX_USERS_LAUNCHPAD = "sshks_users_launchpad"
INDEX_USERS_GITLAB = "sshks_users_gitlab"
INDEX_USERS_GITHUB = "sshks_users_github"
SRC_INDICES = [
    #INDEX_USERS_GITHUB,
    # INDEX_USERS_GITLAB,
    INDEX_USERS_LAUNCHPAD
]
DEST_INDEX = "sshks_keys_launchpad_202501"
MAPPINGS = {
    "properties": {
        "entry": {"type": "integer"},
        "alg": {"type": "keyword"},
        "outer_alg": {"type": "keyword"},
        "length": {"type": "integer"},
        "source": {
            "type": "object",
            "properties": {"index": {"type": "keyword"}, "id": {"type": "keyword"}},
        },
        "fpr": {"type": "keyword"},
        "params": {
            "type": "object",
            "properties": {
                "e": {"type": "text"},
                "n": {"type": "text"},
                "p": {"type": "text"},
                "q": {"type": "text"},
                "g": {"type": "text"},
                "y": {"type": "text"},
                "curve": {"type": "keyword"},
                "Q": {"type": "text"},
                "key": {"type": "text"},
            },
        },
    }
}

class KeyIterator(object):
    def __init__(
        self,
        batchsize=5000,
        request_timeout=60,
        scroll="60m",
        bulk_threads=16,
        parallel=None,
    ):
        self.batchsize = batchsize
        self.request_timeout = request_timeout
        self.scroll = scroll
        self.bulk_threads = bulk_threads
        if parallel is None:
            parallel = len(os.sched_getaffinity(0)) or os.cpu_count()
        self.parallel = parallel

    def __enter__(self):
        # Connect to Elasticsearch
        self.es = Elasticsearch(
            ES_URL,
            ca_certs=ES_CA_CERT,
            basic_auth=(ES_USER, ES_PASSWORD),
            request_timeout=self.request_timeout,
        )
        if not self.es.ping():
            tqdm.write("Could not reach Elasticsearch. Abort.")
            raise ConnectionError("Could not reach Elasticsearch.")
        # Adjust result window on source indices to allow for larger batch sizes.
        self.es.indices.put_settings(
            index=SRC_INDICES,
            body={"index.max_result_window": max(self.batchsize, 10000)},
        )
        # Drop the index if it already exists.
        if self.es.indices.exists(index=DEST_INDEX):
            self.es.indices.delete(index=DEST_INDEX)
            self.es.indices.create(
                index=DEST_INDEX,
                mappings=MAPPINGS,
                settings={"number_of_shards": 1, "number_of_replicas": 2},
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Close elastic connection and progress bars.
        self.es.close()

    def get_total_key_count(self):
        return self.es.count(index=SRC_INDICES)["count"]

    def run(self):
        # Query to retrieve all keys from the source indices.
        query = {
            "query": {
                "nested": {
                    "path": "publicKeys",
                    "query": {
                        "bool": {
                            "filter": {
                                "script": {
                                    "script": {
                                        "source": "doc['key'].length > 0",
                                        "lang": "painless",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        key_cnt = self.get_total_key_count()

        # Retrieve all keys from the source indices and map
        # them to new indexing actions for the destination index.
        aggregated_users = [
            hit
            for hit in tqdm(
                scan(
                    self.es,
                    index=SRC_INDICES,
                    scroll=self.scroll,
                    query=query,
                    size=self.batchsize,
                    request_timeout=self.request_timeout,
                ),
                desc="Keys retrieved",
                total=key_cnt,
                unit="keys",
                position=0,
            )
        ]

        actions = []
        errors = []
        with WorkerPool(n_jobs=self.parallel, keep_alive=True) as pool:
            results = pool.imap_unordered(
                process, make_single_arguments(aggregated_users, generator=False)
            )
            for result in tqdm(
                results,
                desc="Keys processed",
                total=len(aggregated_users),
                unit="keys",
                position=1,
            ):
                for key in result["_keys"]:
                    action = {
                        "_op_type": "index",
                        "_index": DEST_INDEX,
                        "_source": key,
                    }
                    actions.append(action)
                for err in result["_errors"]:
                    errors.append(err)
                    tqdm.write(err)

        # Merge actions with the same key fingerprint.
        entry = 0
        fpr_to_action = dict()
        for action in tqdm(
            actions, desc="Duplicate keys merged", unit="keys", position=2
        ):
            fpr = action["_source"]["fpr"]
            # If the fpr is already in the list, append the source, effectively merging the two records.
            if fpr in fpr_to_action:
                fpr_to_action[fpr]["_source"]["source"].extend(
                    action["_source"]["source"]
                )
            else:
                fpr_to_action[fpr] = action
                fpr_to_action[fpr]["_source"]["entry"] = entry
                entry += 1
        actions = list(fpr_to_action.values())

        with tqdm(
            total=len(actions),
            position=3,
            desc="Unique keys indexed",
            unit="keys",
        ) as indexbar:
            # Wrap the actions list in a generator that increments the indexbar.
            def actions_with_indexbar():
                for action in actions:
                    indexbar.update(1)
                    yield action

            # Create generator and bulk insert into the database.
            actions_generator = actions_with_indexbar()
            failures = 0
            for success, info in parallel_bulk(
                self.es,
                actions_generator,
                thread_count=self.bulk_threads,
                chunk_size=1000,
                queue_size=self.bulk_threads * 2,
            ):
                if not success:
                    failures += 1
                    tqdm.write(
                        f"A document failed insertion into destination index: {info}"
                    )
            tqdm.write(
                f"Indexed {len(actions) - failures} keys of "
                + str(len(actions))
                + " keys"
            )

        # At the end, write the errors to a file.
        with open("01-extract-keys-sshks-errors.txt", "w") as f:
            f.write("Errors:\n")
            f.write("\n".join(errors))


def pad_b64(b64):
    return b64 + "=" * (-len(b64) % 4)


def parse_launchpad_key(raw):
    def parse_key(key_b64):
        blob = base64.b64decode(key_b64)
        # Extract outer algorithm identifier required by load_ssh_public_key
        alg_len = int.from_bytes(blob[:4], "big")
        outer_alg = blob[4 : 4 + alg_len].decode("ascii")
        return (
            outer_alg,
            blob,
            load_ssh_public_key(f"{outer_alg} {key_b64}".encode("utf-8")),
        )

    try:
        key_b64 = pad_b64(raw.replace("\r\n", "").replace(" ", ""))
        return parse_key(key_b64)
    except Exception as e:
        key_b64 = pad_b64("".join(raw.replace("\r\n", "").split(" ")[:-1]))
        try:
            return parse_key(key_b64)
        except Exception:
            raise e


def parse_key_obj(key_obj, src):
    raw = key_obj["key"]
    outer_alg = None
    blob = None
    sshpubkey = None
    if src["index"] == INDEX_USERS_LAUNCHPAD:
        outer_alg, blob, sshpubkey = parse_launchpad_key(raw)
    else:
        # Split outer algorithm identifier from key, allowing for an optional comment.
        outer_alg, key_b64 = raw.split(" ", 1)
        if " " in key_b64:
            # Strip comment.
            key_b64, _ = key_b64.split(" ", 1)
        key_b64 = pad_b64(key_b64)
        blob = base64.b64decode(key_b64)
        sshpubkey = load_ssh_public_key(f"{outer_alg} {key_b64}".encode("utf-8"))
    fpr = hashlib.sha256(blob).hexdigest()
    key = {
        "fpr": fpr,
        "alg": None,
        "outer_alg": outer_alg,
        "length": None,
        "params": None,
        "source": [src],
    }
    if sshpubkey["alg"] == "rsa":
        key["alg"] = "rsa"
        # Calculate bit length of key["n"]
        key["length"] = math.ceil(math.log2(sshpubkey["n"]))
        key["params"] = {
            "n": hex(sshpubkey["n"])[2:],
            "e": hex(sshpubkey["e"])[2:],
        }
    elif sshpubkey["alg"] == "dsa":
        key["alg"] = "dsa"
        key["length"] = math.ceil(math.log2(sshpubkey["p"]))
        key["params"] = {
            "y": hex(sshpubkey["y"])[2:],
            "g": hex(sshpubkey["g"])[2:],
            "p": hex(sshpubkey["p"])[2:],
            "q": hex(sshpubkey["q"])[2:],
        }
    elif sshpubkey["alg"] == "ecdsa":
        key["alg"] = "ecdsa"
        key["length"] = sshpubkey["curve"].key_size
        key["params"] = {
            "curve": sshpubkey["curve"].name,
            "Q": sshpubkey["point"].hex(),
        }
    elif sshpubkey["alg"] == "ed25519":
        key["alg"] = "ed25519"
        key["length"] = 256
        key["params"] = {
            "key": sshpubkey["point"].hex(),
        }
    else:
        raise ValueError("Unknown key type " + repr(sshpubkey))
    return key


def process(user_obj):
    keys = []
    errors = []
    src = {"index": user_obj["_index"], "id": user_obj["_id"]}
    for key_index, key_obj in enumerate(user_obj["_source"]["publicKeys"]):
        try:
            keys.append(parse_key_obj(key_obj, src))
        except Exception as e:
            traceback_str = "".join(traceback.format_tb(e.__traceback__))
            err = (
                "Error: "
                + str(e)
                + " for user "
                + user_obj["_id"]
                + " (key index "
                + str(key_index)
                + ") in index "
                + user_obj["_index"]
                + ": "
                + repr(user_obj)
                + "\n"
                + traceback_str
            )
            errors.append(err)
    return {"_user": user_obj, "_keys": keys, "_errors": errors}


if __name__ == "__main__":
    with KeyIterator(batchsize=1000000, parallel=250) as iterator:
        iterator.run()
