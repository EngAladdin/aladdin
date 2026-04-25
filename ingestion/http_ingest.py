"""
http_ingest.py — FastAPI HTTP webhook endpoint for Honeytrap events.
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

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("http_ingest")

HISTORY_KEY: str = os.environ.get("REDIS_HISTORY_KEY", "cerebrum:history")
HISTORY_MAX: int = int(os.environ.get("REDIS_HISTORY_MAX", "2000"))

app = FastAPI(
    title="Cerebrum Event Ingestor",
    version="1.0.0",
    docs_url="/docs" if os.environ.get("DOCS_ENABLED", "false").lower() == "true" else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.post("/ingest/event", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    request: Request,
    x_honeytrap_signature: str = Header(default="", alias="x-honeytrap-signature"),
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Request body is not valid JSON: {exc}")

    events = raw_event if isinstance(raw_event, list) else [raw_event]
    queued = 0
    failed = 0

    for event in events:
        normalized = normalize(event)
        if normalized is None:
            failed += 1
            continue

        # 1. Push to Cerebrum queue (consumed by Cerebrum)
        ok = push_event(normalized)
        if ok:
            queued += 1
        else:
            failed += 1
            continue

        # 2. Append to history list (read by Dashboard — never drained)
        try:
            client = get_client()
            payload = json.dumps(normalized, default=str)
            client.rpush(HISTORY_KEY, payload)
            client.ltrim(HISTORY_KEY, -HISTORY_MAX, -1)
        except Exception as exc:
            log.warning("Could not write to history key: %s", exc)

    log.info("Ingest from %s — total=%d queued=%d failed=%d",
             client_ip, len(events), queued, failed)

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"status": "accepted", "queued": queued, "failed": failed, "total": len(events)},
    )


@app.get("/api/events")
async def get_api_events(limit: int = 200):
    try:
        client = get_client()
        raw_list = client.lrange(HISTORY_KEY, -limit, -1)
        events = []
        for raw in raw_list:
            try:
                events.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
        events.reverse()
        return {"success": True, "events": events, "total": len(events)}
    except Exception as exc:
        log.error("Failed to read history: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"success": False, "events": [], "error": str(exc)},
        )


@app.get("/api/stats")
async def get_api_stats():
    try:
        client = get_client()
        raw_list = client.lrange(HISTORY_KEY, 0, -1)
        by_type: dict = {}
        by_ip: dict = {}
        for raw in raw_list:
            try:
                e = json.loads(raw)
                by_type[e.get("event_type","unknown")] = by_type.get(e.get("event_type","unknown"), 0) + 1
                by_ip[e.get("src_ip","unknown")] = by_ip.get(e.get("src_ip","unknown"), 0) + 1
            except json.JSONDecodeError:
                pass
        return {"success": True, "stats": {"total": len(raw_list), "by_type": by_type, "by_ip": by_ip}}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"success": False, "error": str(exc)})


@app.get("/health")
async def health():
    redis_ok = ping()
    depth = queue_depth() if redis_ok else -1
    try:
        history_len = get_client().llen(HISTORY_KEY) if redis_ok else 0
    except Exception:
        history_len = 0
    payload = {
        "status": "ok" if redis_ok else "degraded",
        "redis": "up" if redis_ok else "down",
        "queue_depth": depth,
        "history_size": history_len,
    }
    code = status.HTTP_200_OK if redis_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=code, content=payload)


@app.get("/metrics")
async def metrics():
    return {"queue_depth": queue_depth()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ingestion.http_ingest:app", host="0.0.0.0", port=8000, workers=1, log_level="info")
