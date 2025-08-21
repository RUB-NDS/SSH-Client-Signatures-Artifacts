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
LOG_FILE="$ARTIFACTS_DIR/logs/setup_env.log"
rm -rf $LOG_FILE && mkdir -p "$ARTIFACTS_DIR/logs" && touch $LOG_FILE

function log() {
    echo -e "$1" | tee -a $LOG_FILE
}

# Check that the script is invoked without sudo
if [[ $SUDO_USER ]]; then
   log "${RED}[!] This script should not be run with sudo.${NC}"
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

# Check for sudo rights and keep sudo from timing out
sudo -v
while sleep 300; do sudo -v; done &

function install_docker() {
    # Installation steps taken from https://docs.docker.com/engine/install/ubuntu/
    # Uninstall conflicting packages (should not be present)
    log "${GREEN}[+] Installing Docker...${NC}"
    log "    - Uninstalling conflicting packages..."
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get -y remove $pkg >> $LOG_FILE 2>&1; done

    # Receiving Docker's official GPG key
    log "    - Receiving Docker's official GPG key..."
    sudo apt-get update >> $LOG_FILE 2>&1
    sudo apt-get install -y ca-certificates curl >> $LOG_FILE 2>&1
    sudo install -m 0755 -d /etc/apt/keyrings >> $LOG_FILE 2>&1
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc >> $LOG_FILE 2>&1
    sudo chmod a+r /etc/apt/keyrings/docker.asc >> $LOG_FILE 2>&1

    # Add the repository to apt sources
    log "    - Adding Docker's official APT repository..."
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update >> $LOG_FILE 2>&1

    # Install the Docker packages
    log "    - Installing Docker packages..."
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >> $LOG_FILE 2>&1

    log "    - Adding user $USER to the docker group..."
    sudo usermod -aG docker $USER >> $LOG_FILE 2>&1
}

function install_golang() {
    # Installation steps taken from https://go.dev/doc/install
    log "${GREEN}[+] Installing Go 1.25.0...${NC}"
    cd /tmp
    log "    - Downloading Go 1.25.0..."
    wget -q https://go.dev/dl/go1.25.0.linux-amd64.tar.gz >> $LOG_FILE 2>&1
    log "    - Copying Go binaries and setting up profile..."
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz >> $LOG_FILE 2>&1
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile > /dev/null
    export PATH=$PATH:/usr/local/go/bin
    cd $ARTIFACTS_DIR
}

function setup_venv() {
    log "${GREEN}[+] Setting up Python virtual environment for key scraper scripts...${NC}"
    # Install Python and pip
    log "    - Installing Python 3.11 and pip..."
    sudo add-apt-repository -y ppa:deadsnakes/ppa >> $LOG_FILE 2>&1
    sudo apt-get install -y python3.11 python3.11-venv >> $LOG_FILE 2>&1

    # Create a virtual environment
    log "    - Creating virtual environment..."
    python3.11 -m venv venv >> $LOG_FILE 2>&1
    log "    - Entering virtual environment..."
    source venv/bin/activate

    # Install required packages
    log "    - Installing required packages..."
    pip install -r $ARTIFACTS_DIR/code/key_scraper/scripts/requirements.txt >> $LOG_FILE 2>&1
    pip install -r $ARTIFACTS_DIR/code/rsa_factorability_tool/requirements.txt >> $LOG_FILE 2>&1

    # Deactivate the virtual environment
    log "    - Deactivating virtual environment..."
    deactivate
}

function install_sagemath() {
    log "${GREEN}[+] Installing SageMath 10.3 as a Python library into the virtual environment...${NC}"
    # Install SageMath dependencies
    log "    - Installing SageMath dependencies..."
    sudo apt-get install -y binutils make m4 perl flex python3.11 tar bc gcc libbz2-dev bzip2 g++ ca-certificates patch \
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
    source venv/bin/activate
    log "    - Installing sage_conf 10.3 (this will take a while)..."
    pip install -v sage_conf==10.3 >> $LOG_FILE 2>&1
    # Install pkg wheels built by sage_conf
    log "    - Installing pkg wheels built by sage_conf..."
    pip install $(sage-config SAGE_SPKG_WHEELS)/*.whl sage_setup==10.3 >> $LOG_FILE 2>&1

    # Finally, install SageMath
    log "    - Installing sagemath-standard 10.3 (this will take a while)..."
    pip install --no-build-isolation -v sagemath-standard==10.3 >> $LOG_FILE 2>&1

    log "    - Deactivating virtual environment..."
    deactivate
}

function install_additional_dependencies() {
    log "${GREEN}[+] Installing additional dependencies...${NC}"
    sudo apt-get install -y screen >> $LOG_FILE 2>&1
}

function build_keyscraper() {
    # Build the key_scraper tool
    log "${GREEN}[+] Building the key_scraper tool...${NC}"
    cd $ARTIFACTS_DIR/code/key_scraper
    go build >> $LOG_FILE 2>&1
    cd $ARTIFACTS_DIR
}

function build_nonce_sampler() {
    # Build the nonce_sampler tool
    log "${GREEN}[+] Building the nonce_sampler tool...${NC}"
    cd $ARTIFACTS_DIR/code/nonce_sampler
    go build >> $LOG_FILE 2>&1
    cd $ARTIFACTS_DIR
}

function start_elasticsearch() {
    log "${GREEN}[+] Starting Elasticsearch stack...${NC}"
    cd $ARTIFACTS_DIR/code/env_docker
    # User has not relogged in yet, so we need to use sudo here
    sudo docker compose up -d > /dev/null 2>&1
    cd $ARTIFACTS_DIR
}

function copy_elasticsearch_ca_cert() {
    log "${GREEN}[+] Copying Elasticsearch CA certificate...${NC}"
    sudo docker cp sshks-es01-1:/usr/share/elasticsearch/config/certs/ca/ca.crt $ARTIFACTS_DIR/code/key_scraper >> $LOG_FILE 2>&1
    sudo chown $USER:$USER $ARTIFACTS_DIR/code/key_scraper/ca.crt
}

install_docker
install_golang
setup_venv
install_sagemath
install_additional_dependencies
build_keyscraper
build_nonce_sampler
start_elasticsearch
copy_elasticsearch_ca_cert
# Stop the sudo background job
kill %1
log "${GREEN}[+] Evaluation environment ready to use! Please reboot before continuing.${NC}"
