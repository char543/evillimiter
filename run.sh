#!/usr/bin/env bash
#
# One-shot launcher for evillimiter.
#
#   - clones the repo to ~/evillimiter if it isn't there yet (otherwise reuses it)
#   - creates the project-local virtualenv and installs deps the first time only
#   - runs the tool as root
#
# Any arguments are passed straight through to evillimiter, e.g.:
#   ./run.sh -i en0
#
# Override the location with EVILLIMITER_DIR=/some/path ./run.sh
#
set -euo pipefail

REPO_URL="https://github.com/char543/evillimiter.git"
REPO_DIR="${EVILLIMITER_DIR:-$HOME/evillimiter}"

# 1. Get the code (clone only if missing; never re-download an existing checkout)
if [ -d "$REPO_DIR/.git" ]; then
    echo "[*] using existing checkout: $REPO_DIR"
else
    echo "[*] cloning $REPO_URL -> $REPO_DIR"
    git clone "$REPO_URL" "$REPO_DIR"
fi

cd "$REPO_DIR"

# 2. Virtualenv + dependencies (first run only; delete .venv to force a rebuild)
if [ -x ".venv/bin/python" ]; then
    echo "[*] virtualenv present; skipping install"
else
    echo "[*] creating virtualenv and installing dependencies"
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip >/dev/null
    .venv/bin/pip install -r requirements.txt
fi

# 3. Run as root. The venv and source stay user-owned; bin/evillimiter disables
#    bytecode writing itself, so no root-owned .pyc files are left behind.
echo "[*] starting evillimiter (sudo)"
exec sudo "$REPO_DIR/.venv/bin/python" "$REPO_DIR/bin/evillimiter" "$@"
