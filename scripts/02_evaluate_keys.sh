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
LOG_FILE="$ARTIFACTS_DIR/logs/evaluate_keys.log"
rm -rf $LOG_FILE && mkdir -p "$ARTIFACTS_DIR/logs" && touch $LOG_FILE

function log() {
    echo -e "$1" | tee -a $LOG_FILE
}

source "$ARTIFACTS_DIR/venv/bin/activate"

# 1. Extract the SSH keys from the user-oriented scraping results
log "${GREEN}[+] Extracting SSH keys from user-oriented scraping results...${NC}"
#python $ARTIFACTS_DIR/code/key_scraper/scripts/01-extract-keys-sshks.py | tee -a $LOG_FILE
# 2. Collect the unique SSH keys from the extracted results
log "${GREEN}[+] Collecting unique SSH keys...${NC}"
#python $ARTIFACTS_DIR/code/key_scraper/scripts/01-extract-keys-sshks-unique.py | tee -a $LOG_FILE
# 3. Generate an initial summary of the extracted SSH keys
log "${GREEN}[+] Generating summary of SSH keys...${NC}"
#python $ARTIFACTS_DIR/code/key_scraper/scripts/02-summarize-keys.py | tee -a $LOG_FILE
# 4. Analyze the keys (excluding batch-gcd)
log "${GREEN}[+] Analyzing SSH keys...${NC}"
#python $ARTIFACTS_DIR/code/key_scraper/scripts/03-analyze-keys.py | tee -a $LOG_FILE
# 4. Analyze the keys (now batch-gcd)
python $ARTIFACTS_DIR/code/key_scraper/scripts/03-batchgcd.py | tee -a $LOG_FILE
# 5. Compile the results
log "${GREEN}[+] Compiling results...${NC}"
python $ARTIFACTS_DIR/code/key_scraper/scripts/05-compile-results.py | tee -a $LOG_FILE
# 6. Collect the affected users
log "${GREEN}[+] Collecting affected users...${NC}"
python $ARTIFACTS_DIR/code/key_scraper/scripts/06-collect-affected-users.py | tee -a $LOG_FILE
log "${GREEN}[+] Done. You may now inspect the scripts' outputs in the results directory.${NC}"

deactivate
