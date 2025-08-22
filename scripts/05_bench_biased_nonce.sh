#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color

# Set up variables for directories
SCRIPTS_DIR=$(dirname "$(readlink -f "$0")")
ARTIFACTS_DIR="$SCRIPTS_DIR/.."
cd $ARTIFACTS_DIR
LOG_FILE="$ARTIFACTS_DIR/logs/bench_putty_success_rate.log"
rm -rf $LOG_FILE && mkdir -p "$ARTIFACTS_DIR/logs" && touch $LOG_FILE

function log() {
    echo -e "$1" | tee -a $LOG_FILE
}

OUTPUT_DIR="$ARTIFACTS_DIR/results/putty_attack"
mkdir -p $OUTPUT_DIR

if [ ! -d "bdd-predicate" ]; then
    log "${GREEN}[+] Cloning malb/bdd-predicate from GitHub...${NC}"
    git clone https://github.com/malb/bdd-predicate
else
    log "${GREEN}[+] bdd-predicate directory already exists${NC}"
fi
cd bdd-predicate

log "${GREEN}[+] Pulling martinralbrecht/bdd-predicate image from Docker hub...${NC}"
docker pull martinralbrecht/bdd-predicate:latest

log "${GREEN}[+] Benchmarking success rate of biased nonce attack...${NC}"
for i in {56..64}; do
    log "    - Running benchmark for m=$i available signatures"
    docker run --rm -v `pwd`:/bdd-predicate \
               -w /bdd-predicate \
               martinralbrecht/bdd-predicate \
               sage -python ecdsa_cli.py benchmark -n 521 -k 512 -m $i -a sieve_pred -t 1024 -j $(nproc) > $OUTPUT_DIR/bdd-sieve_pred-$i.out 2>&1
done

log "${GREEN}[+] Benchmarking success rate of biased nonce attack completed.${NC}"
grep sr: $OUTPUT_DIR/*.out | sed -n 's/.*-\([0-9]\+\)\.out.*sr:[^0-9]*\([0-9]\+\)%.*/\1;\2/p'| sort -n | tee -a $LOG_FILE
cd -
