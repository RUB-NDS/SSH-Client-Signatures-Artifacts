#!/usr/bin/env python3
#
# Usage: ./06-collect-affected-users.py
#
# This script collects the affected users based on the analysis results and writes
# them to separate CSV files, one per platform, for responsible disclosure.
# To do so, the script tracks the originating user documents via the source
# attribute of each key document. Additional key documents to be included
# (e.g. keys affected by batch gcd) can be provided in the BATCH_GCD_RESULTS
# variable.
#

import base64
import csv
from json import loads

from elasticsearch import Elasticsearch

from config import *

RESULTS_IN = f"{RESULTS_DIR}/03-analysis-results.csv"

AFFECTED_USERS_GITHUB_OUT = f"{RESULTS_DIR}/06-affected-users-github.csv"
AFFECTED_USERS_GITLAB_OUT = f"{RESULTS_DIR}/06-affected-users-gitlab.csv"
AFFECTED_USERS_LP_OUT = f"{RESULTS_DIR}/06-affected-users-lp.csv"

# Checks that we deem not impactful enough to justify a report to the platform
# owners (although we offered to supply these as well in our initial report).
# Results with fatal: True are always included (e.g. length_too_short with < 830 bits).
EXCLUDED_CHECKS = [
  # RSA
  'length_too_short',
  'length_not_multiple_of_8',
  'exponent_out_of_range',
  'even_exponent',
  # Ed25519
  'encoding',
  'point_order',
  # ECDSA,
  'invalid_encoding',
  'no_field_element',
  # DSA
  'order_not_160_bit',
]

# As batch gcd is run separately, provide the document ids of vulnerable key documents
# in the unique key index. If left empty, results from batch gcd will not be included.
BATCH_GCD_RESULTS = [ ]

if __name__ == '__main__':
  with (open(RESULTS_IN, 'r') as f,
         open(AFFECTED_USERS_GITHUB_OUT, 'w') as out_github,
         open(AFFECTED_USERS_GITLAB_OUT, 'w') as out_gitlab,
         open(AFFECTED_USERS_LP_OUT, 'w') as out_lp,
         Elasticsearch(
            ES_URL,
            ca_certs=ES_CA_CERT,
            basic_auth=(ES_USER, ES_PASSWORD),
            request_timeout=ES_REQUEST_TIMEOUT,
        ) as es):
    # Init CSV reader and writers
    reader = csv.reader(f)
    writer_github = csv.writer(out_github)
    writer_github.writerow(['username', 'user id', 'key fingerprint', 'check'])
    writer_gitlab = csv.writer(out_gitlab)
    writer_gitlab.writerow(['username', 'user id', 'key fingerprint', 'check'])
    writer_lp = csv.writer(out_lp)
    writer_lp.writerow(['username', 'key fingerprint', 'check'])
    # Process results and write affected users to CSV
    for row in reader:
      idx, doc_id, alg, fpr, sources_json, results_json = row
      results = loads(results_json)
      sources = loads(sources_json)
      reported_checks = [issue['check'] for issue in results['issues'] if issue['fatal'] or not issue['check'] in EXCLUDED_CHECKS]
      if len(reported_checks) > 0:
        # Will be included in our disclosure
        check_str = ','.join(reported_checks)
        fpr_github = 'SHA256:' + base64.b64encode(bytes.fromhex(fpr)).decode('utf-8').replace('=', '')
        for source in sources:
          src_doc = es.get(index=source['index'], id=source['id'])
          if source['index'] == INDEX_USERS_GITHUB:
            writer_github.writerow([
              src_doc['_source']['username'],
              src_doc['_source']['metadata']['remoteId'],
              fpr_github,
              check_str])
          elif source['index'] == INDEX_USERS_GITLAB:
            writer_gitlab.writerow([
              src_doc['_source']['username'],
              src_doc['_source']['metadata']['remoteId'],
              fpr,
              check_str])
          elif source['index'] == INDEX_USERS_LAUNCHPAD:
            writer_lp.writerow([
              src_doc['_source']['username'],
              fpr,
              check_str])
    # Process batch GCD result document ids
    for idx in BATCH_GCD_RESULTS:
      # Will be included in our disclosure
      doc = es.get(index='sshks_keys_unique_202501', id=idx)
      fpr = doc['_source']['fpr']
      check_str = 'batchgcd'
      fpr_github = 'SHA256:' + base64.b64encode(bytes.fromhex(fpr)).decode('utf-8').replace('=', '')
      for source in sources:
        src_doc = es.get(index=source['index'], id=source['id'])
        if source['index'] == INDEX_USERS_GITHUB:
          writer_github.writerow([
            src_doc['_source']['username'],
            src_doc['_source']['metadata']['remoteId'],
            fpr_github,
            check_str])
        elif source['index'] == INDEX_USERS_GITLAB:
          writer_gitlab.writerow([
            src_doc['_source']['username'],
            src_doc['_source']['metadata']['remoteId'],
            fpr,
            check_str])
        elif source['index'] == INDEX_USERS_LAUNCHPAD:
          writer_lp.writerow([
            src_doc['_source']['username'],
            fpr,
            check_str])

