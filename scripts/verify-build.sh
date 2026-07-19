#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "==> uv lock --check"
uv lock --check

echo "==> uv sync --frozen --extra dev"
uv sync --frozen --extra dev

echo "==> pytest"
uv run --frozen pytest -q

echo "==> frontend npm ci + build"
cd frontend
npm ci
npm run build
cd ..

echo "verify-build: ok"
