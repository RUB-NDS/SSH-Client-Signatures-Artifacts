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
LOG_FILE="$ARTIFACTS_DIR/logs/run_scraper.log"
rm -rf $LOG_FILE && mkdir -p "$ARTIFACTS_DIR/logs" && touch $LOG_FILE

function log() {
    echo -e "$1" | tee -a $LOG_FILE
}

# Check that the key_scraper binary exists
if [ ! -f "$ARTIFACTS_DIR/code/key_scraper/SSH-Key-Scraper" ]; then
    log "${RED}[!] SSH-Key-Scraper binary not found! Run setup_env.sh first.${NC}"
    exit 1
fi

# Check that the Elasticsearch CA certificate exists
if [ ! -f "$ARTIFACTS_DIR/code/key_scraper/ca.crt" ]; then
    log "${RED}[!] Elasticsearch CA certificate not found! Run setup_env.sh first.${NC}"
    exit 1
fi

# Check whether a config.json already exists
if [ ! -f "$ARTIFACTS_DIR/code/key_scraper/config.json" ]; then
    log "${YELLOW}[~] No previous config.json found. Generating a new one.${NC}"
    # Read GitHub and GitLab API tokens from user
    read -p "Enter your GitHub API token: " GITHUB_TOKEN
    read -p "Enter your GitLab API token: " GITLAB_TOKEN

    # Copy config.sample.json and replace placeholders
    cp "$ARTIFACTS_DIR/code/key_scraper/config.sample.json" "$ARTIFACTS_DIR/code/key_scraper/config.json"
    sed -i "s|<<< github token >>>|$GITHUB_TOKEN|g" "$ARTIFACTS_DIR/code/key_scraper/config.json"
    sed -i "s|<<< gitlab token >>>|$GITLAB_TOKEN|g" "$ARTIFACTS_DIR/code/key_scraper/config.json"
else
    log "${GREEN}[+] Found existing config.json. Skipping generation.${NC}"
fi

cd "$ARTIFACTS_DIR/code/key_scraper"
log "${GREEN}[+] Invoking key scraper for 24 hours.${NC}"
timeout 1d "./SSH-Key-Scraper" 2>&1 | tee -a $LOG_FILE
log "${GREEN}[+] Key scraper finished. Use scripts/02_evaluate_keys.sh to evaluate the results.${NC}"
cd -
