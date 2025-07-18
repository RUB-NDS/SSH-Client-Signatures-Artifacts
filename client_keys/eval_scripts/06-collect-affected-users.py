#!/usr/bin/env python3

import base64
import csv
from json import loads

from elasticsearch import Elasticsearch

RESULTS_IN = "results/202501/03-analysis-results.csv"

AFFECTED_USERS_GITHUB_OUT = "results/202501/06-affected-users-github.csv"
AFFECTED_USERS_GITLAB_OUT = "results/202501/06-affected-users-gitlab.csv"
AFFECTED_USERS_LP_OUT = "results/202501/06-affected-users-lp.csv"

SRC_INDEX_GITHUB = "sshks_users_github"
SRC_INDEX_GITLAB = "sshks_users_gitlab"
SRC_INDEX_LP = "sshks_users_launchpad"

ES_URL = [
    "https://192.168.66.3:9200",
    "https://192.168.66.5:9200",
    "https://192.168.66.125:9200",
]
ES_CA_CERT = "ca.crt"
ES_USER = "elastic"
ES_PASSWORD = "<<< password >>>"

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

BATCH_GCD_RESULTS = [
  'wOK0YJQBnYvACrn6NWqI',
  'uLOtYJQBnz59Hra6zmt9',
  'tdSxYJQBnYvACrn6CSse',
  'D8KrYJQBnYvACrn6Su8N',
  'aamqYJQBnz59Hra6it6x',
  'QKSoYJQBnz59Hra6bfqE',
  'HDC0YJQBOSGwKIU3BA-M',
  '78KrYJQBnYvACrn6FzG_',
  '7i-zYJQBOSGwKIU34FUA',
  'P72pYJQBnYvACrn6LM_Z',
  'lreuYJQBnz59Hra6yzFg',
  '2L2wYJQBnz59Hra67GRB',
  '436cYJQBnz59Hra6-oIY',
  'jcquYJQBnYvACrn6BYrr',
  'VJWjYJQBnz59Hra6W3by',
  'kAqoYJQBOSGwKIU3mswA',
  '1uedYJQBOSGwKIU38sWU'
]

if __name__ == '__main__':
  with (open(RESULTS_IN, 'r') as f,
         open(AFFECTED_USERS_GITHUB_OUT, 'w') as out_github,
         open(AFFECTED_USERS_GITLAB_OUT, 'w') as out_gitlab,
         open(AFFECTED_USERS_LP_OUT, 'w') as out_lp,
         Elasticsearch(
            ES_URL,
            ca_certs=ES_CA_CERT,
            basic_auth=(ES_USER, ES_PASSWORD),
            request_timeout=60,
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
          if source['index'] == SRC_INDEX_GITHUB:
            writer_github.writerow([
              src_doc['_source']['username'],
              src_doc['_source']['metadata']['remoteId'],
              fpr_github,
              check_str])
          elif source['index'] == SRC_INDEX_GITLAB:
            writer_gitlab.writerow([
              src_doc['_source']['username'],
              src_doc['_source']['metadata']['remoteId'],
              fpr,
              check_str])
          elif source['index'] == SRC_INDEX_LP:
            writer_lp.writerow([
              src_doc['_source']['username'],
              fpr,
              check_str])
    for idx in BATCH_GCD_RESULTS:
      # Will be included in our disclosure
      doc = es.get(index='sshks_keys_unique_202501', id=idx)
      fpr = doc['_source']['fpr']
      check_str = 'batchgcd'
      fpr_github = 'SHA256:' + base64.b64encode(bytes.fromhex(fpr)).decode('utf-8').replace('=', '')
      for source in sources:
        src_doc = es.get(index=source['index'], id=source['id'])
        if source['index'] == SRC_INDEX_GITHUB:
          writer_github.writerow([
            src_doc['_source']['username'],
            src_doc['_source']['metadata']['remoteId'],
            fpr_github,
            check_str])
        elif source['index'] == SRC_INDEX_GITLAB:
          writer_gitlab.writerow([
            src_doc['_source']['username'],
            src_doc['_source']['metadata']['remoteId'],
            fpr,
            check_str])
        elif source['index'] == SRC_INDEX_LP:
          writer_lp.writerow([
            src_doc['_source']['username'],
            fpr,
            check_str])

