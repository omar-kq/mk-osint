#!/usr/bin/env bash
# ⚙ M.K OSINT Framework v2.2 — Kali Linux Installer (PEP 668 Compliant, Zero Command Conflict)
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${APP_DIR}/.venv"
BIN_DIR="${HOME}/.local/bin"

echo "⚡ ⚙ Installing M.K OSINT Framework (v2.2.0) in ${APP_DIR}..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "✖ python3 is required. Run: sudo apt update && sudo apt install -y python3 python3-venv"
    exit 1
fi

python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/pip" install --upgrade -r "${APP_DIR}/requirements.txt"

mkdir -p "${BIN_DIR}"
# Primary zero-conflict command: mk-osint (avoids Plan9 'mk' conflict on Linux)
cat > "${BIN_DIR}/mk-osint" <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${APP_DIR}/mk.py" "\$@"
EOF
chmod +x "${BIN_DIR}/mk-osint"

echo "⚙ Running full automated verification suite..."
"${VENV_DIR}/bin/python" -m unittest discover -s "${APP_DIR}/tests" -v

echo ""
echo "✔ M.K v2.2 installed successfully!"
echo "  Run: ${BIN_DIR}/mk-osint --list-modules"
echo "  Optional Kali native tools: sudo apt install -y libimage-exiftool-perl whois dnsutils theharvester sherlock"
echo "  (Add ~/.local/bin to PATH in ~/.zshrc or ~/.bashrc to run 'mk-osint' from anywhere.)"
