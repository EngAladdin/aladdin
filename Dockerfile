# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile — Cerebrum Event Ingestion Service
# Multi-stage: builder installs deps; runtime is lean with no build tools.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Non-root user for security hardening
RUN addgroup --system cerebrum \
    && adduser --system --ingroup cerebrum --no-create-home cerebrum

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Bring in only the installed packages — no build tools
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Application source (copy only what exists)
COPY ingestion/ ./ingestion/

# Copy adapters only if directory exists (optional)
RUN --mount=type=bind,source=adapters,target=/tmp/adapters \
    if [ -d /tmp/adapters ]; then cp -r /tmp/adapters ./adapters; fi

# Create necessary directories
RUN mkdir -p /var/log/honeytrap /data \
    && chown -R cerebrum:cerebrum /var/log/honeytrap /data \
    && chown -R cerebrum:cerebrum /app

USER cerebrum

EXPOSE 8000

# Single worker for stability (no port conflicts)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Single worker to avoid alternating health check failures
CMD ["uvicorn", "ingestion.http_ingest:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--log-level", "info"]