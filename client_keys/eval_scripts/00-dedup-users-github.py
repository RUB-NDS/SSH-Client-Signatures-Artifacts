#!/usr/bin/env python3
#
# Usage: ./00-dedup-users-github.py
#
# Helper script to remove duplicate GitHub entries in Elasticsearch based on their username.
# For normal evaluation, this script is not required. However, if for whatever reason your
# Elasticsearch instance ended up with duplicates, it may help to resolve this issue.
#
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from tqdm import tqdm

from .config import *

SRC_INDEX=INDEX_USERS_GITHUB
DEST_INDEX=INDEX_USERS_GITHUB + "_dedup"
MAPPINGS={
    "properties": {
        "deleted": {
          "type": "boolean"
        },
        "metadata": {
          "properties": {
            "createdAt": {
              "type": "date"
            },
            "remoteId": {
              "type": "keyword"
            },
            "updatedAt": {
              "type": "date"
            }
          }
        },
        "publicKeys": {
          "type": "nested",
          "properties": {
            "deleted": {
              "type": "boolean"
            },
            "key": {
              "type": "text"
            },
            "metadata": {
              "properties": {
                "fingerprint": {
                  "type": "text"
                }
              }
            },
            "visitedAt": {
              "type": "date"
            }
          }
        },
        "username": {
          "type": "keyword"
        },
        "visitedAt": {
          "type": "date"
        }
    }
}


class UserIterator(object):
    def __init__(self, batchsize=10000):
        self.es = connect_es()
        self.batchsize = batchsize

    def run(self):
        query = {
            "index": [ SRC_INDEX ],
            "size": self.batchsize,
            "sort": { "_doc": "asc" }
        }
        recv_bar = tqdm(total=0, position=0)
        users = []
        tqdm.write("> Retrieving user documents from Elasticsearch")
        finished = False
        while not finished:
            results = self.es.search(**query, preference="_local")
            users_batch = results["hits"]["hits"]
            if len(users_batch) == 0:
                finished = True
                break
            query["search_after"] = users_batch[-1]["sort"]
            users.extend(users_batch)
            recv_bar.total += self.batchsize
            recv_bar.update(self.batchsize)
            recv_bar.display()


        tqdm.write("> Retrieved all user documents from Elasticserach, starting deduplication")

        dedup_bar = tqdm(total=len(users), position=1)
        distinct_usernames = set()
        actions = []
        duplicates = 0
        for user in users:
            if not user["_source"]["username"] in distinct_usernames:
                actions.append({
                    "_op_type": "index",
                    "_index": DEST_INDEX,
                    "_source": user["_source"]
                })
                distinct_usernames.add(user["_source"]["username"])
            else:
                duplicates += 1
            dedup_bar.update(1)

        tqdm.write("> Deduplication done, bulk inserting distinct user documents into target index")
        tqdm.write(f"> Total entries in source index: {len(users)}")
        tqdm.write(f"> Distinct usernames: {len(distinct_usernames)}")
        tqdm.write(f"> Duplicates: {duplicates}")
        tqdm.write(f"> Action count: {len(actions)}")
        bulk(self.es, iter(actions))
        tqdm.write("> Insertion done")


def connect_es():
    es = Elasticsearch(
        ES_URL,
        ca_certs=ES_CA_CERT,
        basic_auth=(ES_USER, ES_PASSWORD),
        request_timeout=ES_REQUEST_TIMEOUT
    )
    # Drop the index if it already exists.
    if not es.indices.exists(index=DEST_INDEX):
        es.indices.create(
            index=DEST_INDEX,
            mappings=MAPPINGS,
            settings={"number_of_shards": NUM_SHARDS, "number_of_replicas": NUM_REPLICAS})
    return es


if __name__ == "__main__":
    iterator = UserIterator(batchsize=BATCH_SIZE)
    iterator.run()
