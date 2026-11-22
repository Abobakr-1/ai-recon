#!/usr/bin/env bash
# airecon installer for Kali Linux / Debian-based systems.
#
#   sudo ./install.sh          system-wide launcher at /usr/local/bin/airecon
#   ./install.sh --user        user venv + launcher in ~/.local/bin
#
# Only installs: python3-venv (if missing), requests, PyYAML, and a launcher.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="system"
[[ "${1:-}" == "--user" ]] && MODE="user"

echo "[*] airecon installer (mode: $MODE)"

# --- python check ---------------------------------------------------------- #
PY="$(command -v python3 || true)"
if [[ -z "$PY" ]]; then
  echo "[!] python3 not found. Install it first: sudo apt install -y python3 python3-venv python3-pip"
  exit 1
fi
echo "[*] python3: $($PY --version)"

# --- venv ------------------------------------------------------------------ #
if [[ "$MODE" == "system" ]]; then
  VENV="/opt/airecon/venv"
  BIN="/usr/local/bin"
  mkdir -p /opt/airecon
else
  VENV="$HOME/.local/share/airecon/venv"
  BIN="$HOME/.local/bin"
  mkdir -p "$HOME/.local/share/airecon" "$BIN"
fi

echo "[*] creating virtualenv at $VENV"
"$PY" -m venv "$VENV" 2>/dev/null || {
  echo "[!] venv creation failed. Install python3-venv: sudo apt install -y python3-venv"
  exit 1
}

echo "[*] installing airecon + dependencies"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$HERE"

# --- launcher -------------------------------------------------------------- #
echo "[*] writing launchers: $BIN/ai-recon and $BIN/airecon"
cat > "$BIN/ai-recon" <<EOF
#!/usr/bin/env bash
exec "$VENV/bin/ai-recon" "\$@"
EOF
cat > "$BIN/airecon" <<EOF
#!/usr/bin/env bash
exec "$VENV/bin/ai-recon" "\$@"
EOF
chmod +x "$BIN/ai-recon" "$BIN/airecon"

echo
echo "[+] installed: AI RECON (developed by AboBakr Mohamed)"
echo "    run:  ai-recon --help     (alias: airecon)"
if [[ "$MODE" == "user" ]]; then
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "    note: add $HOME/.local/bin to PATH:
      echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc" ;;
  esac
fi

# --- optional: kali tooling hint ------------------------------------------ #
echo
echo "[i] Optional complements (native recon tools) if you want them:"
echo "    sudo apt install -y nmap curl jq git"
echo "    pipx install garak   # for payload-level LLM red-teaming after recon"
