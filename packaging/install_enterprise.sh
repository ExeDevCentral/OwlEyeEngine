#!/usr/bin/env bash
# ==============================================================================
# OwlEyeEngine v4.0 Enterprise - Linux Production & Regional Installer
# Automated deployment of Kernel Telemetry, eBPF capabilities & Active Defense
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "    ^...^    OwlEyeEngine v4.0 Enterprise Installer"
echo "   / o o \   Linux Kernel Telemetry & Active Defense"
echo "   |  Y  |   Regional Security Production Edition"
echo "    V v V"
echo -e "${NC}"

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[X] This installer must be run as root (sudo) to configure kernel hooks and systemd.${NC}"
   exit 1
fi

echo -e "${GREEN}[+] Assessing Linux Kernel capabilities...${NC}"
KERNEL_VER=$(uname -r)
echo -e "    Kernel Release: ${CYAN}${KERNEL_VER}${NC}"

# Check eBPF / BPF tracepoint support
if [[ -d "/sys/kernel/debug/tracing" ]]; then
    echo -e "    Kernel Tracing: ${GREEN}[AVAILABLE]${NC}"
else
    echo -e "    Kernel Tracing: ${YELLOW}[MOUNTING /sys/kernel/debug]${NC}"
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
fi

if [[ -d "/sys/fs/bpf" ]]; then
    echo -e "    eBPF Filesystem: ${GREEN}[SUPPORTED]${NC}"
else
    echo -e "    eBPF Filesystem: ${YELLOW}[NOT MOUNTED]${NC}"
fi

# Check firewall backends
if command -v nft &> /dev/null; then
    echo -e "    Firewall Engine: ${GREEN}[nftables DETECTED - Modern Linux Standard]${NC}"
elif command -v iptables &> /dev/null; then
    echo -e "    Firewall Engine: ${GREEN}[iptables DETECTED]${NC}"
else
    echo -e "    Firewall Engine: ${YELLOW}[In-Memory Tracking Fallback]${NC}"
fi

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[X] Python 3.10+ is required but not installed.${NC}"
    exit 1
fi

# Target directory
INSTALL_DIR="/opt/owleye"
echo -e "${GREEN}[+] Deploying code to ${INSTALL_DIR}...${NC}"
mkdir -p "${INSTALL_DIR}"
cp -r ./* "${INSTALL_DIR}/" || true

# Install Python requirements
echo -e "${GREEN}[+] Installing Python dependencies...${NC}"
python3 -m pip install --upgrade pip
python3 -m pip install -r "${INSTALL_DIR}/requirements.txt"
python3 -m pip install -e "${INSTALL_DIR}"

# Install systemd service
SERVICE_PATH="/etc/systemd/system/owleye.service"
if [[ -f "${INSTALL_DIR}/packaging/systemd/owleye.service" ]]; then
    echo -e "${GREEN}[+] Registering systemd daemon service: ${SERVICE_PATH}...${NC}"
    cp "${INSTALL_DIR}/packaging/systemd/owleye.service" "${SERVICE_PATH}"
    systemctl daemon-reload
    systemctl enable owleye.service
    echo -e "${GREEN}[+] Service enabled! Start anytime with: systemctl start owleye${NC}"
fi

echo -e "\n${CYAN}=================================================================${NC}"
echo -e "${GREEN}🎉 OwlEyeEngine v4.0 Enterprise successfully installed!${NC}"
echo -e "CLI Command:            ${CYAN}owleye status${NC} | ${CYAN}owleye kernel${NC}"
echo -e "Start Service:          ${CYAN}systemctl start owleye${NC}"
echo -e "Live Dashboard:         ${CYAN}http://localhost:8000/dashboard${NC}"
echo -e "Prometheus Metrics:     ${CYAN}http://localhost:8000/metrics${NC}"
echo -e "${CYAN}=================================================================${NC}"
