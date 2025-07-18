#!/usr/bin/env python3

from collections import defaultdict
import csv
from json import loads, dumps

from tqdm import tqdm

RESULTS_IN = "results/04-analysis-results-intersection.csv"
RESULTS_OUT= "results/05-compiled-results-intersection.json"

GITHUB_SOURCE_INDEX = "sshks_users_github"
GITLAB_SOURCE_INDEX = "sshks_users_gitlab"
LAUNCHPAD_SOURCE_INDEX = "sshks_users_launchpad"


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
        if source["index"] == GITHUB_SOURCE_INDEX:
            srcs.add("github")
        elif source["index"] == GITLAB_SOURCE_INDEX:
            srcs.add("gitlab")
        elif source["index"] == LAUNCHPAD_SOURCE_INDEX:
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
