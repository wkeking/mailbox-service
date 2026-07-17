# syntax=docker/dockerfile:1.7
# Multi-stage image for linux/arm64 (and optionally linux/amd64) deployment.
# Frontend is baked into the image and served by FastAPI on the same origin.

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
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOME=/app \
    PORT=8000

WORKDIR ${APP_HOME}

# Minimal OS packages for healthcheck and TLS root CAs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY mailbox_service ./mailbox_service
COPY migrations ./migrations

RUN pip install --upgrade pip \
    && pip install .

# Admin SPA assets (vite outDir defaults to dist/)
COPY --from=frontend-builder /frontend/dist ./frontend_dist

# Non-root process for production.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser ${APP_HOME}
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["sh", "-c", "uvicorn mailbox_service.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
