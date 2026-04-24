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

RUN addgroup --system cerebrum \
    && adduser --system --ingroup cerebrum --no-create-home cerebrum

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY ingestion/ ./ingestion/

# ✅ السطر المُصلح — COPY بدل --mount=type=bind
COPY adapters/ ./adapters/

RUN mkdir -p /var/log/honeytrap /data \
    && chown -R cerebrum:cerebrum /var/log/honeytrap /data \
    && chown -R cerebrum:cerebrum /app

USER cerebrum
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

COPY --chmod=755 start.sh ./start.sh
CMD ["./start.sh"]
