#!/usr/bin/env bash
# AI RECON - bootstrap installer (fetched by the one-line curl command).
# Developed by: AboBakr Mohamed
#
#   curl -fsSL https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/bootstrap.sh | sudo bash
#
# This clones the repo to a temp dir and delegates to its install.sh.
set -euo pipefail

REPO_URL="https://github.com/Abobakr-1/ai-recon.git"

command -v git >/dev/null 2>&1 || { echo "[!] git missing: sudo apt install -y git"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[!] python3 missing: sudo apt install -y python3 python3-venv python3-pip"; exit 1; }

TMP="$(mktemp -d)"
echo "[*] fetching AI RECON into $TMP"
git clone --depth 1 "$REPO_URL" "$TMP/ai-recon"
exec bash "$TMP/ai-recon/install.sh" "${1:-}"
