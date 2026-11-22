#!/usr/bin/env bash
# AI RECON - one-command installer for Kali Linux / Debian-based systems.
# Developed by: AboBakr Mohamed
#
# Usage (recommended — one line, no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/bootstrap.sh | sudo bash
#
# Or from a local clone:
#   ./install.sh            # system-wide  -> /usr/local/bin/ai-recon
#   ./install.sh --user     # current user -> ~/.local/bin/ai-recon
#
# On Windows, use the PowerShell installer instead:
#   irm https://raw.githubusercontent.com/Abobakr-1/ai-recon/master/bootstrap.ps1 | iex
#
set -euo pipefail

REPO_URL="https://github.com/Abobakr-1/ai-recon.git"
MODE="${1:-system}"
[[ -z "$MODE" ]] && MODE="system"
[[ "$MODE" == "--user" || "$MODE" == "user" ]] && MODE="user"
[[ "$MODE" == "system" || "$MODE" == "--system" ]] && MODE="system"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31m[!]\033[0m %s\n' "$1" >&2; exit 1; }

step "AI RECON installer (mode: $MODE)"

# --- 1. prerequisites ------------------------------------------------------ #
command -v python3 >/dev/null 2>&1 || die "python3 not found. Run: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
PY="$(command -v python3)"
ok "python3: $($PY --version 2>&1)"

if ! "$PY" -m venv --help >/dev/null 2>&1; then
  die "python3-venv missing. Run: sudo apt install -y python3-venv"
fi

# --- 2. fetch the source (skip if already inside a clone) ------------------ #
SRC_DIR=""
if [[ -f "$(pwd)/pyproject.toml" && -d "$(pwd)/airecon" ]]; then
  SRC_DIR="$(pwd)"
  ok "using local source: $SRC_DIR"
else
  command -v git >/dev/null 2>&1 || die "git not found. Run: sudo apt install -y git"
  SRC_DIR="$(mktemp -d)/ai-recon"
  step "cloning $REPO_URL"
  git clone --depth 1 "$REPO_URL" "$SRC_DIR" || die "git clone failed"
fi

# --- 3. install into a virtualenv ------------------------------------------ #
if [[ "$MODE" == "system" ]]; then
  VENV="/opt/ai-recon/venv"; BIN="/usr/local/bin"
else
  VENV="$HOME/.local/share/ai-recon/venv"; BIN="$HOME/.local/bin"
fi
mkdir -p "$(dirname "$VENV")" "$BIN"

step "creating virtualenv: $VENV"
"$PY" -m venv "$VENV"

# venv layout differs: Linux/macOS -> bin/, Windows -> Scripts/
if [[ -x "$VENV/bin/python" ]]; then VPY="$VENV/bin/python"; else VPY="$VENV/Scripts/python.exe"; fi
[[ -x "$VPY" ]] || die "virtualenv python not found at $VENV"

step "installing AI RECON + dependencies (requests, PyYAML)"
"$VPY" -m pip install --quiet --upgrade pip
"$VPY" -m pip install --quiet "$SRC_DIR"

# --- 4. launchers ---------------------------------------------------------- #
# Resolve the venv console-script path for either layout.
if [[ -x "$VENV/bin/ai-recon" ]]; then VEXE="$VENV/bin/ai-recon"; else VEXE="$VENV/Scripts/ai-recon.exe"; fi
step "writing launchers into $BIN"
for name in ai-recon airecon; do
  cat > "$BIN/$name" <<EOF
#!/usr/bin/env bash
exec "$VEXE" "\$@"
EOF
  chmod +x "$BIN/$name"
  ok "installed: $BIN/$name"
done

# --- 5. verify + PATH hint ------------------------------------------------- #
step "verifying installation"
"$BIN/ai-recon" --version || die "verification failed"

if [[ "$MODE" == "user" ]]; then
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) printf '\n\033[1;33m[!]\033[0m Add this to your shell, then reopen the terminal:\n'
       printf '    echo '\''export PATH="$HOME/.local/bin:$PATH"'\'' >> ~/.bashrc && source ~/.bashrc\n' ;;
  esac
fi

printf '\n\033[1;32m[+] Done.\033[0m  AI RECON is installed (developed by AboBakr Mohamed).\n'
printf '    Try:   ai-recon --help\n'
printf '    First: ai-recon scope --allow <your-target> --save\n\n'
