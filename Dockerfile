# syntax=docker/dockerfile:1.7
# Multi-stage image for linux/arm64 (and optionally linux/amd64) deployment.
# Frontend is baked into the image and served by FastAPI on the same origin.
#
# Layer strategy (runtime stage):
#   1) OS packages + appuser          — rare changes
#   2) third-party Python deps        — only when pyproject.toml dependencies change
#   3) application code + migrations  — frequent, small
#   4) frontend dist                  — only when frontend changes
# This keeps docker pull small when only business code is updated.
#
# Important: do NOT copy README or application sources into the dependency layer.
# README edits previously invalidated the ~27MB site-packages layer on every push.

ARG NODE_IMAGE=node:22-bookworm-slim
# Keep the image runtime aligned with local development (Python 3.14).
ARG PYTHON_IMAGE=python:3.14-slim-bookworm

# ---------------------------------------------------------------------------
# Stage 1: build the React admin UI
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS frontend-builder

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
# Empty base URL => browser calls same-origin /api/v1/... behind the Python server.
ENV VITE_API_BASE_URL=
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: Python runtime
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOME=/app \
    PORT=8000 \
    PYTHONPATH=/app

WORKDIR ${APP_HOME}

# Minimal OS packages for healthcheck and TLS root CAs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user early so later COPY --chown does not need chown -R.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

# Dependency lock input only — must not include README or application sources.
COPY pyproject.toml ./

# Install third-party packages listed in pyproject.toml [project].dependencies.
# Application code is loaded later via PYTHONPATH=/app (not pip-installed).
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip \
    && python -c "import subprocess, tomllib; from pathlib import Path; deps = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))['project']['dependencies']; assert deps, 'pyproject.toml has no [project].dependencies'; subprocess.check_call(['pip', 'install', '--no-cache-dir', *deps])"

# Application sources (small, frequently changing layers).
COPY --chown=appuser:appuser mailbox_service ./mailbox_service
COPY --chown=appuser:appuser migrations ./migrations
COPY --chown=appuser:appuser README.md ./README.md

# Admin SPA assets (vite outDir defaults to dist/)
COPY --from=frontend-builder --chown=appuser:appuser /frontend/dist ./frontend_dist

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["sh", "-c", "uvicorn mailbox_service.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
