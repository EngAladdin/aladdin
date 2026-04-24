#!/bin/sh
exec uvicorn ingestion.http_ingest:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers 1 \
    --log-level info
