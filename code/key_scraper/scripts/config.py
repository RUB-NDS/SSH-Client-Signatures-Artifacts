# This file contains common configuration options for all evaluation scripts

##
## Processing
##

# Number of documents fetched from the Elasticsearch per batch
# This value must not exceed the maximum result window of the Elasticsearch index
# By default, it is set to 10,000 documents per batch
BATCH_SIZE=10000

# Number of parallel processing workers
# Adjust this value based on your system's capabilities (CPU cores, RAM, etc.)
PARALLEL_WORKERS=16

# Number of threads to use when using Elasticsearch bulk operations
# Adjust this value based on your system's capabilities (CPU cores, RAM, etc.)
BULK_THREADS=16

# Path to the results directory (relative or absolute)
RESULTS_DIR="results"

##
## Elasticsearch
##

ES_URL="https://localhost:9200"
ES_CA_CERT="../ca.crt"
ES_USER="elastic"
ES_PASSWORD="elasticsearchpass"
ES_REQUEST_TIMEOUT=30

##
## Indices
##

# Number of shards and replicas per index
# All indices created by the evaluation pipeline will have the same settings
NUM_SHARDS=1
NUM_REPLICAS=2

# User indices created by the scraper
INDEX_USERS_GITHUB="sshks_users_github"
INDEX_USERS_GITLAB="sshks_users_gitlab"
INDEX_USERS_LAUNCHPAD="sshks_users_launchpad"

# Key indices created by ./01-extract-keys-sshks.py
INDEX_KEYS_GITHUB="sshks_keys_github"
INDEX_KEYS_GITLAB="sshks_keys_gitlab"
INDEX_KEYS_LAUNCHPAD="sshks_keys_launchpad"

# Unique key index created by ./01-extract-keys-sshks-unique.py
INDEX_KEYS_UNIQUE="sshks_keys_unique"
