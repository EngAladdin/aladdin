"""
queue.py — Redis-backed event queue with retry / exponential-backoff.

Design goals
------------
* At-least-once delivery: events are pushed to a Redis list.  The consumer
  (Cerebrum) POPs from the same list.  If the consumer crashes mid-process,
  a separate "inflight" key can be used for acknowledgement (not implemented
  here — kept simple for the integration sprint).
* Retry with exponential backoff: transient Redis failures (network blip,
  restart) are retried up to MAX_RETRIES times before dropping the event
  and logging an alert.
* Single connection pool shared across the process lifecycle.
"""

import json
import logging
import os
import time
from typing import Optional

import redis

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIS_HOST: str = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_DB:   int = int(os.environ.get("REDIS_DB", "0"))
QUEUE_KEY:  str = os.environ.get("REDIS_QUEUE_KEY", "cerebrum:events")

# Retry parameters
MAX_RETRIES:   int   = int(os.environ.get("QUEUE_MAX_RETRIES", "5"))
INITIAL_DELAY: float = float(os.environ.get("QUEUE_INITIAL_DELAY", "0.5"))  # seconds
BACKOFF_FACTOR: float = 2.0   # doubles each attempt
MAX_DELAY:      float = 30.0  # cap at 30 s

# ---------------------------------------------------------------------------
# Redis connection pool (module-level singleton)
# ---------------------------------------------------------------------------

_pool: Optional[redis.ConnectionPool] = None


def _get_pool() -> redis.ConnectionPool:
    """
    Return (and lazily create) the shared connection pool.
    A pool is used so every push_event() call doesn't open a new TCP connection.
    """
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,        # ✅ أضف السطر ده
            decode_responses=True,   # strings, not bytes
            max_connections=20,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        log.info("Redis pool initialised → %s:%s db=%s", REDIS_HOST, REDIS_PORT, REDIS_DB)
    return _pool


def get_client() -> redis.Redis:
    """Return a Redis client backed by the shared pool."""
    return redis.Redis(connection_pool=_get_pool())


# ---------------------------------------------------------------------------
# Queue helpers
# ---------------------------------------------------------------------------

def push_event(event: dict) -> bool:
    """
    Serialize *event* to JSON and RPUSH it onto the Redis list at QUEUE_KEY.

    Retries on transient errors using exponential backoff.  After MAX_RETRIES
    failures the event is dropped and False is returned — the caller should
    log / alert accordingly.

    Args:
        event: A normalized CerebrumEvent dict (from normalize.py).

    Returns:
        True if the event was successfully queued; False otherwise.
    """
    try:
        payload = json.dumps(event, default=str)
    except (TypeError, ValueError) as exc:
        log.error("Cannot serialize event to JSON: %s | event=%s", exc, event)
        return False

    delay = INITIAL_DELAY
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            client = get_client()
            queue_len = client.rpush(QUEUE_KEY, payload)
            log.debug(
                "Event queued (id=%s) → %s [depth=%d]",
                event.get("event_id", "?"),
                QUEUE_KEY,
                queue_len,
            )
            return True

        except redis.RedisError as exc:
            log.warning(
                "Redis push failed (attempt %d/%d): %s — retrying in %.1fs",
                attempt,
                MAX_RETRIES,
                exc,
                delay,
            )
            if attempt < MAX_RETRIES:
                time.sleep(delay)
                delay = min(delay * BACKOFF_FACTOR, MAX_DELAY)

    # All retries exhausted
    log.error(
        "Dropped event after %d retries (id=%s). Redis may be unreachable.",
        MAX_RETRIES,
        event.get("event_id", "?"),
    )
    return False


def queue_depth() -> int:
    """
    Return the current number of events waiting in the Redis queue.
    Useful for health-check endpoints and monitoring dashboards.
    Returns -1 if Redis is unreachable.
    """
    try:
        return get_client().llen(QUEUE_KEY)
    except redis.RedisError as exc:
        log.warning("Could not read queue depth: %s", exc)
        return -1


def ping() -> bool:
    """
    Lightweight connectivity check — returns True if Redis responds.
    Used by health-check routes.
    """
    try:
        return get_client().ping()
    except redis.RedisError:
        return False
