#!/bin/bash
# OwlEyeEngine v4.0 Enterprise - Linux Quick Installer
set -e

echo "🦉 Initializing OwlEyeEngine v4.0 Enterprise Installation..."

if [ "$EUID" -ne 0 ]; then
  echo "[!] Warning: Running as non-root. Kernel hooks and active firewall mitigation may require sudo privileges."
fi

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[X] Python 3 is required but not installed."
    exit 1
fi

echo "[+] Installing Python dependencies..."
python3 -m pip install -r requirements.txt || pip install -r requirements.txt
python3 -m pip install -e . || true

echo "[+] Starting OwlEye Engine v4.0 Enterprise..."
python3 sentry.py
