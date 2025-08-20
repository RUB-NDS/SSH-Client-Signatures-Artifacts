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

# Disable PIP version check
export PIP_DISABLE_PIP_VERSION_CHECK=1

# Set up variables for directories
SCRIPTS_DIR=$(dirname "$(readlink -f "$0")")
ARTIFACTS_DIR="$SCRIPTS_DIR/.."
cd $ARTIFACTS_DIR
LOG_FILE="$SCRIPTS_DIR/setup_env.log"
rm -rf $LOG_FILE && touch $LOG_FILE

function log() {
    echo -e "$1" | tee -a $LOG_FILE
}

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   log "${RED}[!] This script must be run as root.${NC}"
   exit 1
fi

# Check Ubuntu version
source /etc/lsb-release
if [[ $DISTRIB_ID != "Ubuntu" || $DISTRIB_RELEASE != "24.04" ]]; then
   log "${RED}[!] This script does not support Ubuntu versions other than 24.04. Refer to the README for further details.${NC}"
   exit 1
fi

# Check available CPU cores
CPU_CORES=$(nproc)
if [[ $CPU_CORES -lt 16 ]]; then
   log "${YELLOW}[~] We recommend having at least 16 CPU cores available when running these artifacts. Running with less may impact performance.${NC}"
fi

# Check available RAM
RAM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
REQUIRED_RAM=$((64 * 1024 * 1024))
if [[ $RAM_TOTAL -lt $REQUIRED_RAM ]]; then
   log "${YELLOW}[~] We recommend having at least 64GB of RAM available when running these artifacts. Running with less may impact performance.${NC}"
fi

function install_docker() {
    # Installation steps taken from https://docs.docker.com/engine/install/ubuntu/
    # Uninstall conflicting packages (should not be present)
    log "${GREEN}[+] Installing Docker...${NC}"
    log "    - Uninstalling conflicting packages..."
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do apt-get -y remove $pkg >> $LOG_FILE 2>&1; done

    # Add Docker's official GPG key
    log "    - Adding Docker's official GPG key..."
    apt-get update >> $LOG_FILE 2>&1
    apt-get install -y ca-certificates curl >> $LOG_FILE 2>&1
    install -m 0755 -d /etc/apt/keyrings >> $LOG_FILE 2>&1
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc >> $LOG_FILE 2>&1
    chmod a+r /etc/apt/keyrings/docker.asc >> $LOG_FILE 2>&1

    # Add the repository to apt sources
    log "    - Adding Docker's official APT repository..."
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
    tee /etc/apt/sources.list.d/docker.list >> $LOG_FILE 2>&1
    apt-get update >> $LOG_FILE 2>&1

    # Install the Docker packages
    log "    - Installing Docker packages..."
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >> $LOG_FILE 2>&1

    # If the script got invoked by another user via sudo, we add them to the docker group
    if [[ $SUDO_USER ]]; then
        log "    - Adding user $SUDO_USER to the docker group..."
        usermod -aG docker $SUDO_USER >> $LOG_FILE 2>&1
    fi
}

function install_golang() {
    # Installation steps taken from https://go.dev/doc/install
    log "${GREEN}[+] Installing Go 1.25.0...${NC}"
    cd /tmp
    log "    - Downloading Go 1.25.0..."
    wget -q https://go.dev/dl/go1.25.0.linux-amd64.tar.gz >> $LOG_FILE 2>&1
    log "    - Copying Go binaries and setting up profile..."
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz >> $LOG_FILE 2>&1
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    cd $ARTIFACTS_DIR
}

function setup_venv() {
    log "${GREEN}[+] Setting up Python virtual environment for evaluation scripts...${NC}"
    # Install Python and pip
    log "    - Installing Python 3.11 and pip..."
    add-apt-repository -y ppa:deadsnakes/ppa >> $LOG_FILE 2>&1
    apt-get install -y python3.11 python3.11-venv >> $LOG_FILE 2>&1

    # Create a virtual environment
    log "    - Creating virtual environment..."
    cd $ARTIFACTS_DIR/code/key_scraper/scripts
    python3.11 -m venv .venv >> $LOG_FILE 2>&1
    log "    - Entering virtual environment..."
    source .venv/bin/activate

    # Install required packages
    log "    - Installing required packages..."
    pip install -r requirements.txt >> $LOG_FILE 2>&1

    # Deactivate the virtual environment
    log "    - Deactivating virtual environment..."
    deactivate
    cd $ARTIFACTS_DIR
}

function install_sagemath() {
    log "${GREEN}[+] Installing SageMath 10.3 as a Python library...${NC}"
    # Install SageMath dependencies
    log "    - Installing SageMath dependencies..."
    apt-get install -y binutils make m4 perl flex python3.11 tar bc gcc libbz2-dev bzip2 g++ ca-certificates patch \
            pkg-config xz-utils libffi-dev libboost-dev libcdd-dev libcdd-tools cliquer libcliquer-dev cmake curl \
            libcurl4-openssl-dev ecl libec-dev eclib-tools gmp-ecm libecm-dev fflas-ffpack libflint-dev libfplll-dev \
            libfreetype-dev gap libgap-dev libgc-dev gengetopt libgf2x-dev gfan gfortran libgiac-dev xcas libgivaro-dev \
            glpk-utils libglpk-dev libgmp-dev libgsl-dev libiml-dev texinfo lcalc liblfunction-dev libatomic-ops-dev \
            libbraiding-dev libgd-dev libhomfly-dev liblzma-dev liblinbox-dev liblrcalc-dev libm4ri-dev \
            libm4rie-dev maxima meson libmpc-dev libmpfi-dev libmpfr-dev nauty libncurses5-dev ninja-build libntl-dev \
            libopenblas-dev openssl libssl-dev palp pari-gp2c libpari-dev pari-doc pari-elldata pari-galdata pari-galpol \
            pari-seadata patchelf libplanarity-dev planarity libppl-dev ppl-dev libprimesieve-dev libpython3.11-dev \
            libqhull-dev libreadline-dev librw-dev singular singular-doc libsingular4-dev \
            libsqlite3-dev sqlite3 libsuitesparse-dev libsymmetrica2-dev sympow tachyon tox libzmq3-dev >> $LOG_FILE 2>&1

    # Install sage_conf first
    log "    - Entering virtual environment..."
    cd $ARTIFACTS_DIR/code/key_scraper/scripts
    source .venv/bin/activate
    log "    - Installing sage_conf 10.3 (this will take a long time)..."
    pip install sage_conf==10.3 >> $LOG_FILE 2>&1
    # Install pkg wheels built by sage_conf
    log "    - Installing pkg wheels built by sage_conf..."
    pip install $(sage-config SAGE_SPKG_WHEELS)/*.whl sage_setup==10.3 >> $LOG_FILE 2>&1

    # Finally, install SageMath
    log "    - Installing sagemath-standard 10.3..."
    pip install --no-build-isolation sagemath-standard==10.3 >> $LOG_FILE 2>&1

    log "    - Deactivating virtual environment..."
    deactivate
    cd $ARTIFACTS_DIR
}

function build_keyscraper() {
    # Build the SSH-Key-Scraper tool
    log "${GREEN}[+] Building SSH-Key-Scraper tool...${NC}"
    cd $ARTIFACTS_DIR/code/key_scraper
    go build >> $LOG_FILE 2>&1
    cd $ARTIFACTS_DIR
}

function build_nonce_sampler() {
    # Build the SSH-Client-Nonce-Sampler tool
    log "${GREEN}[+] Building SSH-Client-Nonce-Sampler tool...${NC}"
    cd $ARTIFACTS_DIR/code/nonce_sampler
    go build >> $LOG_FILE 2>&1
    cd $ARTIFACTS_DIR
}

function start_elasticsearch() {
    log "${GREEN}[+] Starting Elasticsearch...${NC}"
    cd $ARTIFACTS_DIR/code/env_docker
    docker compose up -d >> $LOG_FILE 2>&1
    cd $ARTIFACTS_DIR
}

install_docker
install_golang
setup_venv
install_sagemath
build_keyscraper
build_nonce_sampler
start_elasticsearch
