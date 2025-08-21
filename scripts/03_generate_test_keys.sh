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
LOG_FILE="$ARTIFACTS_DIR/logs/generate_test_keys.log"
rm -rf $LOG_FILE && mkdir -p "$ARTIFACTS_DIR/logs" && touch $LOG_FILE

function log() {
    echo -e "$1" | tee -a $LOG_FILE
}

source "$ARTIFACTS_DIR/venv/bin/activate"

log "${GREEN}[+] Generating test SSH keys...${NC}"
python $ARTIFACTS_DIR/code/key_scraper/scripts/07-generate-test-keys.py | tee -a $LOG_FILE

deactivate
