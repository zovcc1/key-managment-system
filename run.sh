#!/usr/bin/env bash
# One-command launcher for Linux/macOS: sets up the venv, applies migrations,
# builds the console if needed, and starts the API on http://127.0.0.1:8010
# (which also serves the built web console). See README.md for details.
#
# Usage:
#   ./run.sh            start (setup is idempotent, safe to re-run)
#   ./run.sh --seed      force re-seed the demo dataset
#   ./run.sh --dev       dev mode: uvicorn --reload (8010) + vite (5173)
set -euo pipefail
cd "$(dirname "$0")"

SEED=false
DEV=false
for arg in "$@"; do
  case "$arg" in
    --seed) SEED=true ;;
    --dev) DEV=true ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

echo "[1/6] Checking Python..."
PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "$PYTHON_BIN" ]]; then
  echo "python3 not found. Install Python 3.11+ from https://www.python.org/downloads/ and re-run." >&2
  exit 1
fi
PY_OK=$("$PYTHON_BIN" -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')
if [[ "$PY_OK" != "1" ]]; then
  echo "Python 3.11+ required, found $("$PYTHON_BIN" --version)." >&2
  exit 1
fi

echo "[2/6] Setting up virtual environment (.venv)..."
if [[ ! -d .venv ]]; then
  "$PYTHON_BIN" -m venv .venv
fi
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -e ".[dev]"

echo "[3/6] Restoring secret file permissions (git does not preserve file modes)..."
[[ -f data/root.passphrase ]] && chmod 0400 data/root.passphrase
[[ -f data/root.salt ]] && chmod 0400 data/root.salt

echo "[4/6] Applying database migrations..."
DB_EXISTED=true
[[ -f keyring.db ]] || DB_EXISTED=false
./.venv/bin/alembic upgrade head

if [[ "$SEED" == true ]] || [[ "$DB_EXISTED" == false ]]; then
  echo "[5/6] Seeding demo dataset..."
  ./.venv/bin/python -m keyring.seed
  chmod 0400 data/root.passphrase data/root.salt
else
  echo "[5/6] Database already present, skipping seed (use --seed to force)."
fi

echo "[6/6] Preparing console (web/dist)..."
if [[ ! -f web/dist/index.html ]]; then
  if command -v npm >/dev/null 2>&1; then
    (cd web && npm install && npm run build)
  else
    echo "npm not found and web/dist is missing — the API will run without the console UI." >&2
  fi
fi

echo
echo "Demo API keys (X-Api-Key header on POST /api/session):"
echo "  Alice (key-admin): demo-key-admin-alice-9f2a"
echo "  Bob   (key-admin): demo-key-admin-bob-7c31"
echo "  Carol (auditor):   demo-auditor-carol-1e88"
echo "  Dan   (operator):  demo-operator-dan-4b60"
echo

if [[ "$DEV" == true ]]; then
  echo "Starting dev mode: API on :8010 (reload) + console on :5173 ..."
  ./.venv/bin/uvicorn keyring.main:app --reload --port 8010 &
  API_PID=$!
  trap 'kill $API_PID 2>/dev/null' EXIT
  (cd web && npm install >/dev/null && npm run dev)
else
  echo "Starting API + console at http://127.0.0.1:8010 ..."
  exec ./.venv/bin/uvicorn keyring.main:app --port 8010
fi
