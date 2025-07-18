#!/usr/bin/env python3
import csv
import os
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from tqdm import tqdm
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

ES_URL = [
    "https://192.168.66.3:9200",
    "https://192.168.66.5:9200",
    "https://192.168.66.125:9200",
]
ES_CA_CERT = "ca.crt"
ES_USER = "elastic"
ES_PASSWORD = "<<< password >>>"

FORCE_RESCAN = False
DBINDEX = "sshks_keys_unique_202501"
SOURCES = ["sshks_users_github", "sshks_users_gitlab", "sshks_users_launchpad"]

CSV_OUT = "results/202501/02-summary.csv"
LATEX_OUT = "results/202501/02-summary.tex"
RSA_MODULUS_DIST_IMG_OUT = "results/202501/02-summary-rsa-modulus-dist.png"
RSA_MODULUS_CDF_IMG_OUT = "results/202501/02-summary-rsa-modulus-cdf.png"
ECDSA_CURVE_DIST_IMG_OUT = "results/202501/02-summary-ecdsa-curve-dist.png"


def create_stats():
    return {
        "outer_alg": defaultdict(int),
        "alg": defaultdict(int),
        "rsa.e": defaultdict(int),
        "rsa.length": defaultdict(int),
    }


class KeySummarizer(object):
    def __init__(self, batchsize=100000, request_timeout=60, scroll="60m"):
        self.batchsize = batchsize
        self.request_timeout = request_timeout
        self.scroll = scroll

    def __enter__(self):
        # Connect to Elasticsearch
        self.es = Elasticsearch(
            ES_URL,
            ca_certs=ES_CA_CERT,
            basic_auth=(ES_USER, ES_PASSWORD),
            request_timeout=self.request_timeout,
        )
        if not self.es.ping():
            raise ValueError("Unable to connect to Elasticsearch.")
        # Adjust result window on source index to allow for larger batch sizes.
        self.es.indices.put_settings(
            index=DBINDEX,
            body={"index.max_result_window": max(self.batchsize, 10000)},
        )
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.es.close()

    def get_total_key_count(self):
        return self.es.count(index=DBINDEX)["count"]

    def summarize(self, stats):
        query = {"query": {"match_all": {}}}
        key_cnt = self.get_total_key_count()
        keys = [
            hit["_source"]
            for hit in tqdm(
                scan(
                    self.es,
                    index=DBINDEX,
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
        for key in tqdm(keys, desc="Keys summarized", unit="keys", position=1):
            unique_sources = list(set([ks["index"] for ks in key["source"]]))
            for source in unique_sources + ["total"]:
                stat = stats[source]
                stat["outer_alg"][key["outer_alg"]] += 1
                stat["alg"][key["alg"]] += 1
                if key["alg"] == "rsa":
                    stat["rsa.e"][key["params"]["e"]] += 1
                    stat["rsa.length"][key["length"]] += 1
        for source in stats:
            stats[source]["alg"]["total"] = sum(stats[source]["alg"].values())
            stats[source]["outer_alg"]["total"] = sum(
                stats[source]["outer_alg"].values()
            )
            stats[source]["rsa.e"]["total"] = sum(stats[source]["rsa.e"].values())
            stats[source]["rsa.length"]["total"] = sum(
                stats[source]["rsa.length"].values()
            )


def output_stats_csv(fh, stats):
    writer = csv.writer(fh)
    writer.writerow(["Source", "Statistic", "Match", "Count"])
    writer.writerows(
        [
            (source, stat_name, match, count)
            for source, source_stats in stats.items()
            for stat_name, stat in source_stats.items()
            for match, count in sorted(stat.items(), key=lambda x: x[1], reverse=True)
        ]
    )


def input_stats_csv(fh):
    reader = csv.reader(fh)
    stats = defaultdict(create_stats)
    skip_header = True
    for row in reader:
        if skip_header:
            skip_header = False
            continue
        source, stat_name, match, count = row
        stats[source][stat_name][match] = int(count)
    return stats


def output_stats_latex(fh, stats):
    fh.write(r"\begin{tabular}{lrrrrrrrr}" + "\n")
    fh.write(r"\toprule" + "\n")
    fh.write(
        r"& \multicolumn{4}{c}{June 2023} & \multicolumn{4}{c}{January 2025} \\" + "\n"
    )
    fh.write(r"\cmidrule(lr){2-5}\cmidrule(lr){6-9}" + "\n")
    fh.write(
        r"Algorithm & GitHub & GitLab & Launchpad & Unique & GitHub & GitLab & Launchpad & Unique \\"
        + "\n"
    )
    fh.write(r"\midrule" + "\n")
    rows = [("RSA", "rsa"), ("Ed25519", "ed25519"), ("ECDSA", "ecdsa"), ("DSA", "dsa")]
    for rowcap, row in rows:
        line = [f"{rowcap}", ""]
        for source in SOURCES:
            count = stats[source]["alg"][row]
            if stats[source]["alg"]["total"] == 0:
                percentage = 0
            else:
                percentage = count / stats[source]["alg"]["total"] * 100
            line[0] += f" & {percentage:.2f}\\%"
            line[1] += r" & \countstyle{" + f"{count}" + r"}"
        count = stats["total"]["alg"][row]
        if stats["total"]["alg"]["total"] == 0:
            percentage = 0
        else:
            percentage = count / stats["total"]["alg"]["total"] * 100
        line[0] += f" & {percentage:.2f}\\%"
        line[1] += r" & \countstyle{" + f"{count}" + r"}"
        fh.write(line[0] + r" \\" + "\n")
        fh.write(line[1] + r" \\" + "\n")
    fh.write(r"\midrule" + "\n")
    fh.write(r"Total")
    for source in SOURCES:
        count = stats[source]["alg"]["total"]
        fh.write(r" & \totalstyle{" + f"{count}" + r"}")
    count = stats["total"]["alg"]["total"]
    fh.write(r" & \totalstyle{" + f"{count}" + r"} \\" + "\n")
    fh.write(r"\bottomrule" + "\n")
    fh.write(r"\end{tabular}" + "\n")


def generate_rsa_modulus_dist(stats):
    plt.figure(figsize=(8, 2))
    frequency = {}
    for source in SOURCES:
        frequency[source] = defaultdict(int)
        for size in map(int, stats[source]["rsa.length"].keys() - ["total"]):
            if size < 2048:
                frequency[source]["lt2048"] += stats[source]["rsa.length"][str(size)]
            elif 2048 <= size < 3072:
                frequency[source]["lt3072"] += stats[source]["rsa.length"][str(size)]
            elif 3072 <= size < 4096:
                frequency[source]["lt4096"] += stats[source]["rsa.length"][str(size)]
            else:
                frequency[source]["gte4096"] += stats[source]["rsa.length"][str(size)]
            frequency[source]["total"] += stats[source]["rsa.length"][str(size)]
        left = [0, 0, 0]
        size_bin_to_style = {
            "lt2048": ("n < 2048", "lightcoral", "\\\\"),
            "lt3072": ("2048 ≤ n < 3072", "khaki", "//"),
            "lt4096": ("3072 ≤ n < 4096", "chartreuse", "\\\\"),
            "gte4096": ("4096 ≤ n", "forestgreen", "//"),
        }
    for size_bin in ["lt2048", "lt3072", "lt4096", "gte4096"]:
        freq_normalized = [
            (
                frequency[source][size_bin] / frequency[source]["total"]
                if frequency[source]["total"] > 0
                else 0
            )
            for source in reversed(SOURCES)
        ]
        print(size_bin, freq_normalized)
        label, color, hatch = size_bin_to_style[size_bin]
        plt.barh(
            ["Launchpad", "GitLab", "GitHub"],
            freq_normalized,
            left=left,
            label=label,
            color=color,
            hatch=hatch,
        )
        left = [sum(x) for x in zip(left, freq_normalized)]
    plt.grid(axis="x", alpha=0.5)
    plt.xlim(0, 1)
    plt.xticks(np.arange(0, 1.1, 0.1))
    plt.legend(ncol=4, loc="lower left", bbox_to_anchor=(-0.011, -0.4))
    plt.savefig(RSA_MODULUS_DIST_IMG_OUT, dpi=300, bbox_inches="tight")
    plt.close()


def generate_rsa_modulus_cdf(stats):
    plt.figure(figsize=(6, 6))
    source_to_style = {
        SOURCES[0]: ("GitHub", "red", 1.5, "--"),
        SOURCES[1]: ("GitLab", "green", 1.5, "-."),
        SOURCES[2]: ("Launchpad", "blue", 1.5, ":"),
        "total": ("Total", "black", 3, "-"),
    }
    for source in ["total"] + SOURCES:
        length_sorted = np.array(
            sorted(map(int, stats[source]["rsa.length"].keys() - ["total"]))
        )
        length_freq = np.array(
            [stats[source]["rsa.length"][str(length)] for length in length_sorted]
        )
        length_cdf = 1 - (np.cumsum(length_freq) / np.sum(length_freq))
        label, color, linewidth, linestyle = source_to_style[source]
        plt.plot(
            length_sorted,
            length_cdf,
            label=label,
            drawstyle="steps-post",
            color=color,
            linewidth=linewidth,
            linestyle=linestyle,
        )
    plt.xlabel("RSA Modulus Bit Length", fontsize=12)
    plt.xticks(np.arange(0, 4097, 1024))
    plt.xlim(0, 4608)
    plt.ylabel("Complementary Cumulative Distribution (CCDF)", fontsize=12)
    plt.grid(alpha=0.5)
    plt.legend()
    plt.savefig(RSA_MODULUS_CDF_IMG_OUT, dpi=300, bbox_inches="tight")
    plt.close()


def generate_ecdsa_curve_dist(stats):
    plt.figure(figsize=(8, 2))
    frequency = {}
    for source in SOURCES:
        frequency[source] = defaultdict(int)
        ecdsa_algs = [
            alg for alg in stats[source]["outer_alg"].keys() if "ecdsa" in alg
        ]
        for alg in ecdsa_algs:
            if "nistp256" in alg:
                frequency[source]["nistp256"] += stats[source]["outer_alg"][alg]
            elif "nistp384" in alg:
                frequency[source]["nistp384"] += stats[source]["outer_alg"][alg]
            elif "nistp521" in alg:
                frequency[source]["nistp521"] += stats[source]["outer_alg"][alg]
            else:
                print(
                    "WARNING - Unable to classify curve while generating ECDSA curve distribution plot: ",
                    alg,
                )
            frequency[source]["total"] += stats[source]["outer_alg"][alg]
    left = [0, 0, 0]
    curve_to_style = {
        "nistp256": ("NIST P-256", "skyblue", "\\\\"),
        "nistp384": ("NIST P-384", "deepskyblue", "xx"),
        "nistp521": ("NIST P-521", "royalblue", "//"),
    }
    for curve in ["nistp256", "nistp384", "nistp521"]:
        freq_normalized = [
            (
                frequency[source][curve] / frequency[source]["total"]
                if frequency[source]["total"] > 0
                else 0
            )
            for source in reversed(SOURCES)
        ]
        label, color, hatch = curve_to_style[curve]
        plt.barh(
            ["Launchpad", "GitLab", "GitHub"],
            freq_normalized,
            left=left,
            label=label,
            color=color,
            hatch=hatch,
        )
        left = [sum(x) for x in zip(left, freq_normalized)]
    plt.grid(axis="x", alpha=0.5)
    plt.xlim(0, 1)
    plt.xticks(np.arange(0, 1.1, 0.1))
    plt.legend()
    plt.savefig(ECDSA_CURVE_DIST_IMG_OUT, dpi=300, bbox_inches="tight")
    plt.close()


STATS = defaultdict(create_stats)
if __name__ == "__main__":
    if not FORCE_RESCAN and os.path.exists(CSV_OUT):
        with open(CSV_OUT, "r") as fh:
            STATS = input_stats_csv(fh)
    else:
        with KeySummarizer() as iterator:
            iterator.summarize(STATS)
        with open(CSV_OUT, "w") as fh:
            output_stats_csv(fh, STATS)
    with open(LATEX_OUT, "w") as fh:
        output_stats_latex(fh, STATS)
    generate_rsa_modulus_cdf(STATS)
    generate_rsa_modulus_dist(STATS)
    generate_ecdsa_curve_dist(STATS)
