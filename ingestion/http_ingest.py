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
"""
import json
import logging
import os

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ingestion.normalize import normalize
from ingestion.queue import ping, push_event, queue_depth, get_client, QUEUE_KEY
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
    docs_url="/docs" if os.environ.get("DOCS_ENABLED", "false").lower() == "true" else None,
    redoc_url=None,
)

# ---------------------------------------------------------------------------
# CORS — allow Dashboard (and any origin) to call this API from the browser
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helper: extract client IP through common proxy headers
# ---------------------------------------------------------------------------

def _get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Routes — ingest
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
    body: bytes = await request.body()

    client_ip = _get_client_ip(request)
    ok, reason = validate_request(client_ip, body, x_honeytrap_signature)
    if not ok:
        log.warning("Rejected request from %s: %s", client_ip, reason)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

    try:
        raw_event = json.loads(body)
    except json.JSONDecodeError as exc:
        log.warning("Malformed JSON from %s: %s", client_ip, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Request body is not valid JSON: {exc}",
        )

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

    log.info("Ingest from %s — total=%d queued=%d failed=%d", client_ip, len(events), queued, failed)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"status": "accepted", "queued": queued, "failed": failed, "total": len(events)},
    )


# ---------------------------------------------------------------------------
# Routes — dashboard API
# ---------------------------------------------------------------------------

@app.get("/api/events", summary="Get events from Redis queue for Dashboard")
async def get_api_events(limit: int = 200):
    """
    Returns up to `limit` recent events from the Redis queue.
    Called by the Dashboard frontend to display live data.
    """
    try:
        client = get_client()
        raw_list = client.lrange(QUEUE_KEY, -limit, -1)
        events = []
        for raw in raw_list:
            try:
                events.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
        events.reverse()  # newest first
        return {"success": True, "events": events, "total": len(events)}
    except Exception as exc:
        log.error("Failed to read events from Redis: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"success": False, "events": [], "error": str(exc)},
        )


@app.get("/api/stats", summary="Aggregated stats from Redis queue")
async def get_api_stats():
    """Basic aggregated statistics over all queued events."""
    try:
        client = get_client()
        raw_list = client.lrange(QUEUE_KEY, 0, -1)
        by_type: dict = {}
        by_ip: dict = {}
        for raw in raw_list:
            try:
                e = json.loads(raw)
                t  = e.get("event_type", "unknown")
                ip = e.get("src_ip", "unknown")
                by_type[t]  = by_type.get(t, 0)  + 1
                by_ip[ip]   = by_ip.get(ip, 0)   + 1
            except json.JSONDecodeError:
                pass
        return {
            "success": True,
            "stats": {"total": len(raw_list), "by_type": by_type, "by_ip": by_ip},
        }
    except Exception as exc:
        log.error("Failed to compute stats: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"success": False, "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Routes — health / metrics
# ---------------------------------------------------------------------------

@app.get("/health", summary="Health check")
async def health():
    redis_ok = ping()
    depth    = queue_depth() if redis_ok else -1
    payload  = {
        "status":      "ok" if redis_ok else "degraded",
        "redis":       "up" if redis_ok else "down",
        "queue_depth": depth,
    }
    code = status.HTTP_200_OK if redis_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=code, content=payload)


@app.get("/metrics", summary="Basic queue metrics")
async def metrics():
    return {"queue_depth": queue_depth()}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ingestion.http_ingest:app",
        host="0.0.0.0",
        port=8000,
        workers=1,
        log_level="info",
    )
