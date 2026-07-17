# syntax=docker/dockerfile:1.7
# Multi-stage image for linux/arm64 (and optionally linux/amd64) deployment.
# Frontend is baked into the image and served by FastAPI on the same origin.
#
# Layer strategy (runtime stage):
#   1) OS packages + appuser          — rare changes
#   2) third-party Python deps        — only when pyproject.toml deps change
#   3) application code + migrations  — frequent, small
#   4) frontend dist                  — only when frontend changes
# This keeps docker pull small when only business code is updated.

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

# Metadata only — dependency list lives here; keep this layer above application sources.
COPY --chown=appuser:appuser pyproject.toml README.md ./

# Install third-party dependencies without baking application sources into this layer.
# Placeholder package satisfies setuptools package discovery; the local project is
# uninstalled afterwards so only site-packages third-party wheels remain.
RUN --mount=type=cache,target=/root/.cache/pip \
    mkdir -p mailbox_service \
    && printf '# placeholder for dependency install\n' > mailbox_service/__init__.py \
    && pip install --upgrade pip \
    && pip install . \
    && (pip uninstall -y mailbox-service || true) \
    && rm -rf mailbox_service build dist *.egg-info

# Application sources (small, frequently changing layers).
# Loaded via PYTHONPATH=/app — avoids reinstalling the local package on every code change.
COPY --chown=appuser:appuser mailbox_service ./mailbox_service
COPY --chown=appuser:appuser migrations ./migrations

# Admin SPA assets (vite outDir defaults to dist/)
COPY --from=frontend-builder --chown=appuser:appuser /frontend/dist ./frontend_dist

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["sh", "-c", "uvicorn mailbox_service.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
