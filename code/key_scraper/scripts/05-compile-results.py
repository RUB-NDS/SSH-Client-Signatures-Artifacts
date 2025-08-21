#!/usr/bin/env python3
#
# Usage: ./05-compile-results.py
#
# This script aggregates the results of the key analysis into a single JSON file.
#

from collections import defaultdict
import csv
import os
from json import loads, dumps

from tqdm import tqdm

from config import *

RESULTS_IN = f"{RESULTS_DIR}/03-analysis-results.csv"
RESULTS_OUT= f"{RESULTS_DIR}/05-compiled-results.json"


def make_results_dict():
    return {
        "combined": defaultdict(int),
        "github": defaultdict(int),
        "gitlab": defaultdict(int),
        "launchpad": defaultdict(int),
    }

RESULTS = {
    "dsa": make_results_dict(),
    "rsa": make_results_dict(),
    "ecdsa": make_results_dict(),
    "ed25519": make_results_dict(),
}

def map_sources(sources):
    srcs = set()
    for source in sources:
        if source["index"] == INDEX_USERS_GITHUB:
            srcs.add("github")
        elif source["index"] == INDEX_USERS_GITLAB:
            srcs.add("gitlab")
        elif source["index"] == INDEX_USERS_LAUNCHPAD:
            srcs.add("launchpad")
    return list(srcs)

def count_result(alg, result, sources):
    for source in sources + ['combined']:
        RESULTS[alg][source]["_total"] += 1
        if result["compromised"]:
            RESULTS[alg][source]["_compromised"] += 1
        for issue in result["issues"]:
            RESULTS[alg][source][issue["check"]] += 1
            if issue['fatal']:
                RESULTS[alg][source]['_fatal+' + issue['check']] += 1
            if issue['check'] == 'small_factor' and not issue['fatal']:
                RESULTS[alg][source]['small_factors+partial_cnt'] += 1
                RESULTS[alg][source]["small_factors+partial_avg_loss"] += int(issue['info'].split(' ')[-2])
            if issue['check'] == 'blocklist':
                blocklist = issue['info'].split(' ')[-4]
                RESULTS[alg][source]['blocklist+'+blocklist] += 1


if __name__ == "__main__":
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    with open(RESULTS_IN, "r") as f:
        csv_reader = csv.reader(f)
        row_cnt = sum(1 for _ in csv_reader)
        f.seek(0)
        for row in tqdm(csv_reader, total=row_cnt):
            sources = map_sources(loads(row[4]))
            count_result(row[2], loads(row[5]), sources)
        # Compute average small factor loss for partial small factors
        for source in ['github', 'gitlab', 'launchpad', 'combined']:
            if 'small_factors+partial_cnt' in RESULTS['rsa'][source] and RESULTS['rsa'][source]['small_factors+partial_cnt'] > 0:
                RESULTS['rsa'][source]['small_factors+partial_avg_loss'] = RESULTS['rsa'][source]['small_factors+partial_avg_loss'] / RESULTS['rsa'][source]['small_factors+partial_cnt']
        with open(RESULTS_OUT, "w") as out:
            out.write(dumps(RESULTS, indent=2, sort_keys=True))
        print(dumps(RESULTS, indent=2, sort_keys=True))
