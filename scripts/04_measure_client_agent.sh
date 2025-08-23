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
LOG_FILE="$ARTIFACTS_DIR/logs/measure_determinism_bias.log"
rm -rf $LOG_FILE && mkdir -p "$ARTIFACTS_DIR/logs" && touch $LOG_FILE

function log() {
    echo -e "$1" | tee -a $LOG_FILE
}

# Check if the keys directory is already present, if not, create it and generate SSH keys
if [ ! -d "$ARTIFACTS_DIR/code/nonce_sampler/keys" ]; then
    log "${YELLOW}[~] No previously generated keys found under code/nonce_sampler/keys. Generating new ones...${NC}"
    mkdir -p "$ARTIFACTS_DIR/code/nonce_sampler/keys"
    log "    - Generating DSA key pair id_dsa..."
    ssh-keygen -t dsa -f "$ARTIFACTS_DIR/code/nonce_sampler/keys/id_dsa" -N "" >> $LOG_FILE 2>&1
    log "    - Generating ECDSA NIST P-256 key pair id_ecdsa_nistp256..."
    ssh-keygen -t ecdsa -b 256 -f "$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ecdsa_nistp256" -N "" >> $LOG_FILE 2>&1
    log "    - Generating ECDSA NIST P-384 key pair id_ecdsa_nistp384..."
    ssh-keygen -t ecdsa -b 384 -f "$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ecdsa_nistp384" -N "" >> $LOG_FILE 2>&1
    log "    - Generating ECDSA NIST P-521 key pair id_ecdsa_nistp521..."
    ssh-keygen -t ecdsa -b 521 -f "$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ecdsa_nistp521" -N "" >> $LOG_FILE 2>&1
    log "    - Generating Ed25519 key pair id_ed25519..."
    ssh-keygen -t ed25519 -f "$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ed25519" -N "" >> $LOG_FILE 2>&1
else
    log "${GREEN}[+] Previously generated keys found under code/nonce_sampler/keys. Using existing keys...${NC}"
fi

# Let the user select which algorithm to test
ALGORITHMS=("DSA" "ECDSA NIST P-256" "ECDSA NIST P-384" "ECDSA NIST P-521" "Ed25519")
log "${CYAN}[?] Select the public key algorithm to test:${NC}"
select ALGO in "${ALGORITHMS[@]}"; do
    case $ALGO in
        "DSA")
            KEY_PATH="$ARTIFACTS_DIR/code/nonce_sampler/keys/id_dsa"
            break
            ;;
        "ECDSA NIST P-256")
            KEY_PATH="$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ecdsa_nistp256"
            break
            ;;
        "ECDSA NIST P-384")
            KEY_PATH="$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ecdsa_nistp384"
            break
            ;;
        "ECDSA NIST P-521")
            KEY_PATH="$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ecdsa_nistp521"
            break
            ;;
        "Ed25519")
            KEY_PATH="$ARTIFACTS_DIR/code/nonce_sampler/keys/id_ed25519"
            break
            ;;
        *)
            log "${RED}[!] Invalid selection. Please try again.${NC}"
            ;;
    esac
done
log "${GREEN}[+] Selected public key algorithm: $ALGO (key path: $(realpath $KEY_PATH))${NC}"

log "${CYAN}[?] Select the test mode:${NC}"
select MODE in "client" "agent"; do
    case $MODE in
        "client")
            log "${GREEN}[+] Starting nonce_sampler in determinism mode to detect nonce generation method of the client...${NC}"
            log "    => Please connect your client to port 2200 with the appropriate key configured for authentication. Once connected, terminate the connection after a few seconds."
            $ARTIFACTS_DIR/code/nonce_sampler/SSH-Client-Nonce-Sampler determinism -k $KEY_PATH -t 30000
            break
            ;;
        "agent")
            log "${GREEN}[+] Starting nonce_sampler in determinism mode to detect nonce generation method of the agent...${NC}"
            log "    => Make sure your SSH agent is running and available via SSH_AUTH_SOCK. Continue by pressing enter."
            read -r
            $ARTIFACTS_DIR/code/nonce_sampler/SSH-Agent-Nonce-Sampler determinism -k $KEY_PATH -t 30000 -a
            break
            ;;
        *)
            log "${RED}[!] Invalid selection. Please try again.${NC}"
            ;;
    esac
    log "${GREEN}[+] Determinism measurement completed. Starting bias measurement...${NC}"
    case $MODE in
        "client")
            log "${GREEN}[+] Starting nonce_sampler in bias mode to detect potential nonce bias of the client...${NC}"
            log "    => Please connect your client to port 2200 with the appropriate key configured for authentication. Once connected, terminate the connection after a few seconds."
            $ARTIFACTS_DIR/code/nonce_sampler/SSH-Client-Nonce-Sampler bias -j 1 -n 1000 -k $KEY_PATH -t 30000
            break
            ;;
        "agent")
            log "[+] Starting nonce_sampler in bias mode to detect potential nonce bias of the agent..."
            log "[+] Make sure your SSH agent is running and available via SSH_AUTH_SOCK. Continue by pressing enter."
            read -r
            $ARTIFACTS_DIR/code/nonce_sampler/SSH-Agent-Nonce-Sampler bias -j 1 -n 1000 -k $KEY_PATH -t 30000 -a
            break
            ;;
        *)
            log "${RED}[!] Invalid selection. Please try again.${NC}"
            ;;
    esac
done
