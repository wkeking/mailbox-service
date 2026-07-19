#!/usr/bin/env bash
# Local smoke checks that do not require production secrets or a remote browser.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> uv lock check"
uv lock --check

echo "==> pytest (SQLite / unit)"
uv run --frozen pytest -q

if [[ -n "${TEST_DATABASE_URL:-}" && "${TEST_DATABASE_URL}" == mysql* ]]; then
  echo "==> pytest MySQL marker"
  uv run --frozen pytest -m mysql -q
else
  echo "==> skip MySQL tests (set TEST_DATABASE_URL=mysql+pymysql://... to enable)"
fi

echo "==> security static greps"
if rg -n 'commit_open_transaction' mailbox_service; then
  echo "FAIL: commit_open_transaction still present" >&2
  exit 1
fi
if rg -n 'token_version\s*\+=' mailbox_service --glob '!**/tests/**'; then
  echo "FAIL: python-side token_version += found" >&2
  exit 1
fi
if rg -n 'sessionStorage\.(setItem|getItem)' frontend/src; then
  echo "FAIL: sessionStorage token usage found" >&2
  exit 1
fi

echo "==> local smoke OK"
