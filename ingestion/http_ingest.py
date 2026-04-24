"""
http_ingest.py — FastAPI HTTP webhook endpoint for Honeytrap events.

Security model (per-request)
-----------------------------
1. IP allow-list check    — reject non-Honeytrap hosts immediately.
2. HMAC-SHA256 verification — reject tampered or unsigned bodies.
3. Pydantic validation    — reject structurally invalid payloads.
4. Normalization          — convert to Cerebrum format.
5. Redis push             — at-least-once delivery with retry/backoff.

Run locally
-----------
    uvicorn ingestion.http_ingest:app --host 0.0.0.0 --port 8000

Or via Docker Compose (see docker-compose.yml).
"""
# أضف هذا في بداية الملف بعد imports
import sys

# منع استخدام workers متعددين إذا كانوا يسببون مشاكل
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ingestion.http_ingest:app",
        host="0.0.0.0",
        port=8000,
        workers=1,  # قوة على worker واحد للاستقرار
        log_level="info"
    )
import json
import logging
import os

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ingestion.normalize import normalize
from ingestion.queue import ping, push_event, queue_depth
from ingestion.security import validate_request

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("http_ingest")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Cerebrum Event Ingestor",
    description="Accepts Honeytrap webhook events, validates, normalizes, and queues them.",
    version="1.0.0",
    # Don't expose docs in production — set DOCS_ENABLED=true only in dev
    docs_url="/docs" if os.environ.get("DOCS_ENABLED", "false").lower() == "true" else None,
    redoc_url=None,
)


# ---------------------------------------------------------------------------
# Helper: extract client IP through common proxy headers
# ---------------------------------------------------------------------------

def _get_client_ip(request: Request) -> str:
    """
    Resolve the real client IP, honouring X-Forwarded-For when behind a
    trusted reverse proxy.  Falls back to the direct TCP peer address.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # X-Forwarded-For can be a comma-separated chain; leftmost is original
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post(
    "/ingest/event",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Accept a single Honeytrap event",
)
async def ingest_event(
    request: Request,
    x_honeytrap_signature: str = Header(
        default="",
        alias="x-honeytrap-signature",
        description="HMAC-SHA256 of the raw request body (hex or sha256=hex)",
    ),
):
    """
    Accept a single JSON event from a Honeytrap instance.

    Expected headers
    ----------------
    * Content-Type: application/json
    * X-Honeytrap-Signature: sha256=<hex>  (or just the hex digest)

    Returns 202 Accepted on success, 4xx on client errors.
    """
    # --- Read body first (needed for both HMAC and parsing) ---
    body: bytes = await request.body()

    # --- Security: IP + HMAC ---
    client_ip = _get_client_ip(request)
    ok, reason = validate_request(client_ip, body, x_honeytrap_signature)
    if not ok:
        log.warning("Rejected request from %s: %s", client_ip, reason)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

    # --- Parse JSON body ---
    try:
        raw_event = json.loads(body)
    except json.JSONDecodeError as exc:
        log.warning("Malformed JSON from %s: %s", client_ip, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Request body is not valid JSON: {exc}",
        )

    # Support single event dict OR a list of events (batch ingest)
    events = raw_event if isinstance(raw_event, list) else [raw_event]

    queued = 0
    failed = 0

    for event in events:
        normalized = normalize(event)
        if normalized is None:
            log.warning("Normalization failed for event from %s", client_ip)
            failed += 1
            continue

        ok = push_event(normalized)
        if ok:
            queued += 1
        else:
            log.error("Queue push failed for event %s", normalized.get("event_id"))
            failed += 1

    log.info(
        "Ingest from %s — total=%d queued=%d failed=%d",
        client_ip,
        len(events),
        queued,
        failed,
    )

    # Return 202 even if some events failed (caller shouldn't retry everything)
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "queued": queued,
            "failed": failed,
            "total": len(events),
        },
    )


@app.get("/health", summary="Health check")
async def health():
    """
    Lightweight health-check used by Docker / load balancers.
    Returns 200 when Redis is reachable, 503 otherwise.
    """
    redis_ok = ping()
    depth    = queue_depth() if redis_ok else -1

    payload = {
        "status":      "ok" if redis_ok else "degraded",
        "redis":       "up" if redis_ok else "down",
        "queue_depth": depth,
    }
    code = status.HTTP_200_OK if redis_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=code, content=payload)


@app.get("/metrics", summary="Basic queue metrics")
async def metrics():
    """
    Expose queue depth for Prometheus-style scraping or manual inspection.
    """
    return {"queue_depth": queue_depth()}
# أضف في نهاية الملف
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ingestion.http_ingest:app",
        host="0.0.0.0",
        port=8000,
        workers=1,  # Force single worker
        log_level="info"
    )