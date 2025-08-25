import hashlib
import sys
import warnings
import logging

from elasticsearch import Elasticsearch
from tqdm import tqdm
from collections import defaultdict

from tool.data.Database import Database

def start(config, args):
    logger = logging.getLogger()
    warnings.filterwarnings('ignore')
    host = config["elastic"]["host"]
    port = config["elastic"]["port"]
    username = config["elastic"]["username"]
    password = config["elastic"]["password"]
    index = config["elastic"]["index"]
    client = Elasticsearch(
        hosts=[f"https://{host}:{port}"],
        basic_auth=(username, password),
        verify_certs=False
    )
    warnings.filterwarnings('default')

    if not client.indices.exists(index=index):
        client.indices.create(index=index)

    logger.info("Opening Database")
    db = Database(config)
    logger.info("Starting insert")
    db.start_insert()
    try:
        scroll_time = "1d"
        for ind in [index]:
            logger.info(f"Starting to go through {ind}")
            element_count = client.count(index=ind)
            progress = tqdm(total=element_count.get("count"), )
            resp = client.search(
                index=ind,
                scroll=scroll_time,
                size=5000,
                query={"match_all": {}}
            )

            # Obtain scroll ID and first result batch
            scroll_id = resp["_scroll_id"]
            hits = resp["hits"]["hits"]

            logger.info(f"Obtained new scroll id {scroll_id}")
            error_keys = 0
            keytypes = defaultdict(int)
            # Iterate through results
            while hits:
                for hit in hits:
                    try:
                        _id = hit["_id"]
                        _source = hit["_source"]
                        alg = _source["alg"]
                        keytypes[alg] += 1
                        if alg != "rsa": continue
                        user = _source["source"]
                        params = _source["params"]
                        N = int(params["n"], 16)
                        e = int(params["e"], 16)
                        if e > 2**62-1:
                            e = -1
                        key_fingerprint = hashlib.blake2b(str(hit).encode()).digest()
                        key_info = {"user": user, "metadata": {"e": e, "elastic_id": _id, "elastic_index": ind, "fpr": _source["fpr"]}}
                        db.add_ssh_key(N, key_fingerprint, key_info, None)

                    except KeyboardInterrupt:
                        client.clear_scroll(scroll_id=scroll_id)
                        db.finish()
                        client.close()
                        sys.exit(0)
                    except Exception as e:
                        print(e)
                        logger.error(e)
                        logger.error(f"Previous error occurred on hit {hit}")

                # Get next batch
                response = client.scroll(scroll_id=scroll_id, scroll=scroll_time)
                scroll_id = response["_scroll_id"]
                hits = response["hits"]["hits"]

                progress.update(5000)

            client.clear_scroll(scroll_id=scroll_id)
            logger.info(f"{error_keys} could not be parsed")
            logger.info(f"Encountered the following key types: {keytypes}")
    except KeyboardInterrupt:
        db.finish()
        client.close()
        sys.exit(0)
    except Exception as e:
        db.finish()
        client.close()
        logger.error(e)

    db.finish()
    client.close()
