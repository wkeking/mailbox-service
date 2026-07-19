# syntax=docker/dockerfile:1.7
#
# Layered multi-stage image for smaller push/pull when only app code changes.
#
# Frontend:
#   1) package-lock + npm ci     — rare (dependency upgrades)
#   2) sources + npm run build  — frequent
#
# Runtime:
#   1) OS packages + appuser + uv binary  — rare
#   2) uv.lock / pyproject.toml → .venv   — only when Python deps change
#   3) mailbox_service / migrations       — frequent, small
#   4) frontend_dist                      — when UI rebuilds
#
# Push/pull note: unchanged layers keep the same digest and are skipped by the registry.

# Global ARGs are only available until the first FROM unless re-declared per stage.
ARG NODE_IMAGE=node:22-bookworm-slim
ARG PYTHON_IMAGE=python:3.14-slim-bookworm
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.8.4

# ---------------------------------------------------------------------------
# Frontend dependencies (invalidated only by package.json / package-lock.json)
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS frontend-deps

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit --no-fund

# ---------------------------------------------------------------------------
# Frontend build (invalidated by frontend source changes)
# ---------------------------------------------------------------------------
FROM frontend-deps AS frontend-builder

COPY frontend/ ./
ENV VITE_API_BASE_URL=
RUN npm run build

# ---------------------------------------------------------------------------
# uv binary stage (literal image name: BuildKit COPY --from does not expand ARG)
# ---------------------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:0.8.4 AS uv-bin

# ---------------------------------------------------------------------------
# Python third-party deps only (no project install → code changes never touch this)
# ---------------------------------------------------------------------------
ARG PYTHON_IMAGE=python:3.14-slim-bookworm
FROM ${PYTHON_IMAGE} AS python-deps

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:/usr/local/bin:$PATH"

WORKDIR /app

COPY --from=uv-bin /uv /usr/local/bin/uv

# Only dependency manifests — keep this layer stable.
COPY --link pyproject.toml uv.lock ./

# Install locked third-party packages into /app/.venv without the local project.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --no-editable

# ---------------------------------------------------------------------------
# Runtime: reuse .venv, then add only mutable application layers
# ---------------------------------------------------------------------------
ARG PYTHON_IMAGE=python:3.14-slim-bookworm
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOME=/app \
    PORT=8000 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR ${APP_HOME}

# OS base (rare)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

# Numeric chown (10001 = appuser) is required with COPY --link / BuildKit registry
# cache: named users can fail name resolution with "invalid user index: -1".
# Frozen third-party virtualenv from python-deps (large; rarely invalidated)
COPY --from=python-deps --chown=10001:10001 /app/.venv /app/.venv

# Application Python package (frequent, small)
COPY --chown=10001:10001 --link mailbox_service ./mailbox_service

# SQL migrations (occasional)
COPY --chown=10001:10001 --link migrations ./migrations

# Optional docs (tiny; separate so README edits do not bust code layer alone)
COPY --chown=10001:10001 --link README.md ./README.md

# Built admin UI (changes only when frontend is rebuilt)
COPY --from=frontend-builder --chown=10001:10001 /frontend/dist ./frontend_dist

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/ready" || exit 1

# FORWARDED_ALLOW_IPS is injected from the environment; never hardcode '*'.
CMD ["sh", "-c", "uvicorn mailbox_service.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips=${FORWARDED_ALLOW_IPS:-127.0.0.1}"]
